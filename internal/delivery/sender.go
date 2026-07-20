package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"doevoe/internal/store"

	"github.com/emersion/go-smtp"
)

// maxMXAttempts bounds how many MX hosts a single Send will walk
// sequentially. Combined with commandTimeout/submissionTimeout below, this
// keeps a single Send's worst-case duration well inside the worker's
// stale-'sending' requeue cutoff (see the comment on that cutoff in
// worker.go) even against MXs that accept connections but then tarpit.
const maxMXAttempts = 3

// commandTimeout and submissionTimeout override go-smtp's own defaults
// (5m and 12m respectively as of v0.24.0) on every *smtp.Client this
// package creates. Those defaults, times maxMXAttempts hosts walked
// sequentially, could exceed the worker's stale-'sending' cutoff and cause
// a duplicate delivery (see worker.go). These bounds keep the worst case
// per Send well under that cutoff instead.
const (
	commandTimeout    = 2 * time.Minute
	submissionTimeout = 5 * time.Minute
)

type Result struct {
	MXHost   string
	Code     int
	Response string
	Duration time.Duration
	Err      error
	// TLS reports whether the message was delivered over an
	// (opportunistically) STARTTLS-encrypted connection. False both when the
	// server never advertised STARTTLS and when it did but the handshake
	// failed and delivery fell back to plaintext.
	TLS bool
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
	if len(mxs) > maxMXAttempts {
		slog.Debug("capping MX attempts", "domain", rcptDomain, "total", len(mxs), "attempted", maxMXAttempts)
		mxs = mxs[:maxMXAttempts]
	}

	var lastErr error
	var lastHost string
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		lastHost = host
		usedTLS, err := s.deliverTo(ctx, host, e.From, e.To, signed)
		if err == nil {
			return Result{MXHost: host, Code: 250, Response: "accepted", Duration: time.Since(start), TLS: usedTLS}
		}
		lastErr = err
		if Classify(err) == ClassPerm {
			return fail(host, err) // 5xx: don't hammer the next MX
		}
	}
	return fail(lastHost, lastErr)
}

func (s *Sender) deliverTo(ctx context.Context, host, from, to, msg string) (bool, error) {
	c, usedTLS, err := s.connect(ctx, host)
	if err != nil {
		return false, err
	}
	defer c.Close()

	if err := c.Mail(from, nil); err != nil {
		return usedTLS, err
	}
	if err := c.Rcpt(to, nil); err != nil {
		return usedTLS, err
	}
	w, err := c.Data()
	if err != nil {
		return usedTLS, err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return usedTLS, err
	}
	if err := w.Close(); err != nil {
		return usedTLS, err
	}
	return usedTLS, c.Quit()
}

// connect dials host and returns a Client that has already done EHLO with our
// hostname, plus whether the connection ended up TLS-encrypted. If the server
// advertises STARTTLS and TLSConfig is configured, it upgrades to TLS first
// (opportunistic TLS) and re-does EHLO under the encrypted channel, per RFC
// 3207: prior (pre-TLS) EHLO results must be discarded.
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
// fresh EHLO under TLS with our real hostname.
//
// go-smtp's startTLS only wraps the conn with tls.Client(...); it never calls
// Handshake() itself, so a bad cert (self-signed/expired/hostname-mismatch —
// common on real-world MXs) would otherwise surface only later, lazily, on
// whatever I/O happens to trigger it first. The mandatory post-STARTTLS
// c.Hello() call above is exactly that first I/O, so it deterministically
// forces (and surfaces) the handshake here. If that Hello fails with anything
// other than an *smtp.SMTPError, we treat it as a STARTTLS/handshake failure
// and opportunistically redial in plaintext (Postfix "may"-policy style)
// rather than returning a Temp error that would retry identically forever. An
// *smtp.SMTPError there (or from the pre-TLS EHLO inside NewClientStartTLS,
// e.g. a 550 policy rejection) is a real SMTP-level rejection, not a
// TLS/transport problem, so it is surfaced for classification instead of
// triggering a downgrade.
func (s *Sender) connect(ctx context.Context, host string) (*smtp.Client, bool, error) {
	dial := func() (net.Conn, error) {
		d := &net.Dialer{Timeout: 30 * time.Second}
		return d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, s.Port))
	}

	plaintext := func() (*smtp.Client, error) {
		conn, err := dial()
		if err != nil {
			return nil, err
		}
		c := smtp.NewClient(conn)
		c.CommandTimeout = commandTimeout
		c.SubmissionTimeout = submissionTimeout
		if err := c.Hello(s.Hostname); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}

	if s.TLSConfig != nil {
		conn, err := dial()
		if err != nil {
			return nil, false, err
		}
		c, err := smtp.NewClientStartTLS(conn, s.TLSConfig(host))
		if err != nil {
			var se *smtp.SMTPError
			if errors.As(err, &se) {
				return nil, false, err // permanent policy rejection: don't downgrade
			}
			// STARTTLS unsupported, or dial/negotiation failure. That
			// connection is already closed by NewClientStartTLS; redial
			// plaintext.
			c2, err2 := plaintext()
			return c2, false, err2
		}
		c.CommandTimeout = commandTimeout
		c.SubmissionTimeout = submissionTimeout
		if err := c.Hello(s.Hostname); err != nil {
			c.Close()
			var se *smtp.SMTPError
			if errors.As(err, &se) {
				return nil, false, err // real SMTP-level rejection post-TLS
			}
			// Handshake (or other transport) failure: opportunistic
			// downgrade — redial and deliver in plaintext.
			c2, err2 := plaintext()
			return c2, false, err2
		}
		return c, true, nil
	}

	c, err := plaintext()
	return c, false, err
}

// asSMTPError reports whether err wraps an *smtp.SMTPError, setting target if so.
func asSMTPError(err error, target **smtp.SMTPError) bool {
	return errors.As(err, target)
}
