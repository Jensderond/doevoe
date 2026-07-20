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
	"sync"
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

// defaultOverallTimeout is the hard per-Send deadline applied when
// OverallTimeout is unset (zero), which includes struct-literal Senders built
// directly by tests rather than via NewSender. It bounds the entirety of a
// single Send call at the socket level (see the SetDeadline call in connect's
// dial closure below), including phases that would otherwise run under
// go-smtp's own internal timers - most notably smtp.NewClientStartTLS's
// greet+EHLO+STARTTLS handshake, which happens before CommandTimeout/
// SubmissionTimeout are ever assigned to the resulting *smtp.Client. 30m
// leaves the worker's 45m stale-'sending' requeue window (see worker.go)
// comfortable headroom above the worst case.
const defaultOverallTimeout = 30 * time.Minute

type Sender struct {
	Hostname  string
	Port      int
	LookupMX  func(ctx context.Context, domain string) ([]*net.MX, error)
	TLSConfig func(host string) *tls.Config
	// OverallTimeout hard-bounds a single Send call, including the STARTTLS
	// handshake that smtp.NewClientStartTLS performs internally before
	// CommandTimeout/SubmissionTimeout apply. Zero (e.g. a struct-literal
	// Sender built directly in tests) is treated as defaultOverallTimeout.
	OverallTimeout time.Duration
}

func NewSender(hostname string, port int) *Sender {
	return &Sender{
		Hostname: hostname,
		Port:     port,
		LookupMX: func(ctx context.Context, domain string) ([]*net.MX, error) {
			return net.DefaultResolver.LookupMX(ctx, domain)
		},
		TLSConfig:      func(host string) *tls.Config { return &tls.Config{ServerName: host} },
		OverallTimeout: defaultOverallTimeout,
	}
}

func (s *Sender) Send(ctx context.Context, e *store.Email, d *store.Domain) Result {
	overall := s.OverallTimeout
	if overall == 0 {
		overall = defaultOverallTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, overall)
	defer cancel()

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
	// dial opens the TCP connection and immediately arms a watcher (see
	// ctxBoundConn below) that ties the conn's deadline to ctx (bounded by
	// Send's OverallTimeout, above). This is what actually bounds
	// smtp.NewClientStartTLS's internal greet+EHLO+STARTTLS handshake below:
	// that call happens before CommandTimeout/SubmissionTimeout are assigned
	// to the resulting *smtp.Client, so without this it would run under
	// go-smtp's own (much longer) internal defaults instead. tls.Conn
	// delegates SetDeadline/Read/Write to the underlying conn, so the same
	// watcher also bounds the TLS handshake performed when upgrading. Both
	// call sites below - the initial TLS-capable dial and the plaintext
	// (opportunistic-downgrade) redial - go through this closure, so both are
	// covered.
	dial := func() (net.Conn, error) {
		d := &net.Dialer{Timeout: 30 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", host, s.Port))
		if err != nil {
			return nil, err
		}
		return newCtxBoundConn(ctx, conn), nil
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

// ctxBoundConn wraps a net.Conn so that ctx expiring (its OverallTimeout
// deadline elapsing, or the caller's ctx being canceled) forces the conn's
// deadline into the past, immediately failing whatever I/O is in flight (or
// the next I/O issued).
//
// A single SetDeadline call made right after dial is NOT enough here: on
// every command, go-smtp's *smtp.Client itself calls
// conn.SetDeadline(time.Now().Add(CommandTimeout)) and then resets it back
// to no-deadline (time.Time{}) once the command completes (see
// (*Client).greet/(*Client).cmd and the post-DATA reply path in
// github.com/emersion/go-smtp@v0.24.0/client.go) - including inside
// smtp.NewClientStartTLS's internal greet+EHLO+STARTTLS handshake, which
// runs under go-smtp's own default 5m CommandTimeout before this package
// ever gets a chance to assign its own commandTimeout/submissionTimeout. A
// one-time SetDeadline call would simply be overwritten (or erased) by that
// per-command bookkeeping. Watching ctx and forcing the deadline into the
// past the instant it's done applies no matter what go-smtp itself just set
// or cleared, which is what actually makes ctx's deadline (derived from
// Sender.OverallTimeout in Send) a hard cap on every I/O op on this conn.
type ctxBoundConn struct {
	net.Conn
	stop func()
}

func newCtxBoundConn(ctx context.Context, conn net.Conn) *ctxBoundConn {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.SetDeadline(time.Now())
		case <-done:
		}
	}()
	var once sync.Once
	return &ctxBoundConn{Conn: conn, stop: func() { once.Do(func() { close(done) }) }}
}

// Close stops the watcher goroutine before closing the underlying conn, so
// it doesn't linger past the life of the connection. Safe to call multiple
// times (e.g. via both a caller's explicit Close and a deferred one):
// stop() is idempotent, and closing an already-closed net.Conn just returns
// an error, which callers here already ignore or tolerate.
func (c *ctxBoundConn) Close() error {
	c.stop()
	return c.Conn.Close()
}
