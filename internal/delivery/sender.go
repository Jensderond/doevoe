package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"doevoe/internal/store"

	"github.com/emersion/go-smtp"
)

type Result struct {
	MXHost   string
	Code     int
	Response string
	Duration time.Duration
	Err      error
}

type Sender struct {
	Hostname  string
	Port      int
	LookupMX  func(ctx context.Context, domain string) ([]*net.MX, error)
	TLSConfig func(host string) *tls.Config
}

func NewSender(hostname string, port int) *Sender {
	return &Sender{
		Hostname: hostname,
		Port:     port,
		LookupMX: func(ctx context.Context, domain string) ([]*net.MX, error) {
			return net.DefaultResolver.LookupMX(ctx, domain)
		},
		TLSConfig: func(host string) *tls.Config { return &tls.Config{ServerName: host} },
	}
}

func (s *Sender) Send(ctx context.Context, e *store.Email, d *store.Domain) Result {
	start := time.Now()
	fail := func(host string, err error) Result {
		res := Result{MXHost: host, Duration: time.Since(start), Err: err}
		var se *smtp.SMTPError
		if asSMTPError(err, &se) {
			res.Code, res.Response = se.Code, se.Message
		} else if err != nil {
			res.Response = err.Error()
		}
		return res
	}

	msg, err := BuildMessage(e, s.Hostname, time.Now())
	if err != nil {
		return fail("", err)
	}
	signed, err := SignMessage(msg, d)
	if err != nil {
		return fail("", err)
	}

	rcptDomain := e.To[strings.LastIndex(e.To, "@")+1:]
	mxs, err := s.LookupMX(ctx, rcptDomain)
	if err != nil {
		return fail("", err)
	}
	if len(mxs) == 0 {
		mxs = []*net.MX{{Host: rcptDomain, Pref: 0}} // RFC 5321 fallback to A record
	}
	sort.Slice(mxs, func(i, j int) bool { return mxs[i].Pref < mxs[j].Pref })

	var lastErr error
	var lastHost string
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		lastHost = host
		err := s.deliverTo(ctx, host, e.From, e.To, signed)
		if err == nil {
			return Result{MXHost: host, Code: 250, Response: "accepted", Duration: time.Since(start)}
		}
		lastErr = err
		if Classify(err) == ClassPerm {
			return fail(host, err) // 5xx: don't hammer the next MX
		}
	}
	return fail(lastHost, lastErr)
}

func (s *Sender) deliverTo(ctx context.Context, host, from, to, msg string) error {
	c, err := s.connect(ctx, host)
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.Mail(from, nil); err != nil {
		return err
	}
	if err := c.Rcpt(to, nil); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// connect dials host and returns a Client that has already done EHLO with our
// hostname. If the server advertises STARTTLS and TLSConfig is configured, it
// upgrades to TLS first (opportunistic TLS) and re-does EHLO under the
// encrypted channel, per RFC 3207: prior (pre-TLS) EHLO results must be
// discarded.
//
// Deviation from the brief: the installed github.com/emersion/go-smtp@v0.24.0
// has no exported Client.StartTLS method usable on an already-Hello'd client
// (the underlying startTLS is unexported); the only exported way to upgrade
// is smtp.NewClientStartTLS(conn, tlsConfig), which performs its own internal
// EHLO (using "localhost") before upgrading. To keep "EHLO with our hostname"
// true for the connection that actually matters (the one used for
// MAIL/RCPT/DATA), we let NewClientStartTLS do its throwaway pre-TLS EHLO,
// then call the exported c.Hello(s.Hostname) again afterward — startTLS resets
// the client's internal "did hello" state, so this is allowed and triggers a
// fresh EHLO under TLS with our real hostname. If STARTTLS isn't supported (or
// the upgrade fails), NewClientStartTLS has already closed that connection, so
// we redial once and continue in plaintext.
func (s *Sender) connect(ctx context.Context, host string) (*smtp.Client, error) {
	dial := func() (net.Conn, error) {
		d := &net.Dialer{Timeout: 30 * time.Second}
		return d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, s.Port))
	}

	if s.TLSConfig != nil {
		conn, err := dial()
		if err != nil {
			return nil, err
		}
		if c, err := smtp.NewClientStartTLS(conn, s.TLSConfig(host)); err == nil {
			if err := c.Hello(s.Hostname); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		}
		// STARTTLS unsupported or failed; NewClientStartTLS already closed
		// that connection. Fall back to a fresh, plaintext connection.
	}

	conn, err := dial()
	if err != nil {
		return nil, err
	}
	c := smtp.NewClient(conn)
	if err := c.Hello(s.Hostname); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// asSMTPError reports whether err wraps an *smtp.SMTPError, setting target if so.
func asSMTPError(err error, target **smtp.SMTPError) bool {
	return errors.As(err, target)
}
