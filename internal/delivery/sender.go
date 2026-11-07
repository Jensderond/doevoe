package delivery

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/textproto"
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
// go-smtp's own internal timers - most notably the pre-TLS greet+EHLO+
// STARTTLS exchange (startTLS) and the TLS handshake, which happen before
// CommandTimeout/SubmissionTimeout are ever assigned to an *smtp.Client. 30m
// leaves the worker's 45m stale-'sending' requeue window (see worker.go)
// comfortable headroom above the worst case.
const defaultOverallTimeout = 30 * time.Minute

type Sender struct {
	Hostname  string
	Port      int
	LookupMX  func(ctx context.Context, domain string) ([]*net.MX, error)
	TLSConfig func(host string) *tls.Config
	// OverallTimeout hard-bounds a single Send call, including the STARTTLS
	// exchange and TLS handshake that happen before
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
// The pre-TLS greeting/EHLO/STARTTLS exchange is done by startTLS below, not
// by go-smtp: github.com/emersion/go-smtp (v0.24/v0.25) has no exported way to
// STARTTLS on a client that already said Hello, and smtp.NewClientStartTLS
// always sends its pre-TLS EHLO as "localhost". Receivers that check the
// EHLO name against the sending IP's DNS (e.g. VodafoneZiggo) reject that
// with a 421 before we ever get to say our real name, so every EHLO on the
// wire must carry s.Hostname.
//
// tls.Client never calls Handshake() itself, so a bad cert (self-signed/
// expired/hostname-mismatch — common on real-world MXs) would otherwise
// surface only later, lazily, on whatever I/O happens to trigger it first.
// The mandatory post-STARTTLS c.Hello() call below is exactly that first I/O,
// so it deterministically forces (and surfaces) the handshake here. If that
// Hello fails with anything other than an *smtp.SMTPError, we treat it as a
// STARTTLS/handshake failure and opportunistically redial in plaintext
// (Postfix "may"-policy style) rather than returning a Temp error that would
// retry identically forever. An *smtp.SMTPError there (or from the pre-TLS
// EHLO in startTLS, e.g. a 550 policy rejection) is a real SMTP-level
// rejection, not a TLS/transport problem, so it is surfaced for
// classification instead of triggering a downgrade.
func (s *Sender) connect(ctx context.Context, host string) (*smtp.Client, bool, error) {
	// dial opens the TCP connection and immediately arms a watcher (see
	// ctxBoundConn below) that ties the conn's deadline to ctx (bounded by
	// Send's OverallTimeout, above). This is what bounds startTLS's
	// greet+EHLO+STARTTLS exchange below as a whole, on top of its own
	// per-step commandTimeout, since it happens before any *smtp.Client
	// (and its CommandTimeout/SubmissionTimeout) exists. tls.Conn
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
		c, err := s.startTLS(conn, s.TLSConfig(host))
		if err != nil {
			conn.Close()
			var se *smtp.SMTPError
			if errors.As(err, &se) {
				return nil, false, err // permanent policy rejection: don't downgrade
			}
			// STARTTLS unsupported, or negotiation failure: redial
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

// startTLS reads the server greeting, sends EHLO with s.Hostname, and issues
// STARTTLS on conn, then returns a go-smtp client over the TLS-wrapped conn
// that has not yet said Hello (the caller's c.Hello(s.Hostname) is the
// post-TLS EHLO RFC 3207 requires). See connect for why go-smtp's own
// NewClientStartTLS can't be used. SMTP-level replies come back as
// *smtp.SMTPError, so connect's downgrade-vs-surface decision is unchanged;
// "no EHLO" and "no STARTTLS" come back as plain errors, i.e. downgrade.
// The caller closes conn on error.
func (s *Sender) startTLS(conn net.Conn, cfg *tls.Config) (*smtp.Client, error) {
	// Not closed: closing tp would close conn, which we hand to tls.Client.
	tp := textproto.NewConn(conn)
	step := func(expect int, cmd string) (string, error) {
		conn.SetDeadline(time.Now().Add(commandTimeout))
		defer conn.SetDeadline(time.Time{})
		if cmd != "" {
			if err := tp.PrintfLine("%s", cmd); err != nil {
				return "", err
			}
		}
		_, msg, err := tp.ReadResponse(expect)
		var te *textproto.Error
		if errors.As(err, &te) {
			return "", &smtp.SMTPError{Code: te.Code, Message: te.Msg}
		}
		return msg, err
	}

	if _, err := step(220, ""); err != nil {
		return nil, err
	}
	ehlo, err := step(250, "EHLO "+s.Hostname)
	if err != nil {
		var se *smtp.SMTPError
		if errors.As(err, &se) && (se.Code == 500 || se.Code == 502) {
			// No ESMTP means no STARTTLS; plaintext() falls back to HELO.
			return nil, errors.New("smtp: server doesn't support EHLO")
		}
		return nil, err
	}
	// The first line of a multiline EHLO reply is the greeting; the rest
	// are extension keywords, optionally followed by parameters.
	hasSTARTTLS := false
	for _, line := range strings.Split(ehlo, "\n")[1:] {
		if f := strings.Fields(line); len(f) > 0 && strings.EqualFold(f[0], "STARTTLS") {
			hasSTARTTLS = true
		}
	}
	if !hasSTARTTLS {
		return nil, errors.New("smtp: server doesn't support STARTTLS")
	}
	if _, err := step(220, "STARTTLS"); err != nil {
		return nil, err
	}
	// Anything the server sent after its 220 would be read as if it came
	// over TLS (the STARTTLS response-injection class of bug), so refuse.
	if tp.R.Buffered() > 0 {
		return nil, errors.New("smtp: unexpected data after STARTTLS response")
	}
	return smtp.NewClient(greetedConn(tls.Client(conn, cfg))), nil
}

// greetedConn makes a fresh go-smtp client usable on a connection whose 220
// greeting was already consumed (by startTLS, before the TLS upgrade). A new
// smtp.Client always reads a 220 greeting before its first EHLO, and after
// STARTTLS the server doesn't send another, so the client is fed a synthetic
// one; every later read goes to the real conn.
func greetedConn(conn net.Conn) net.Conn {
	return &prefixedConn{Conn: conn, r: io.MultiReader(strings.NewReader("220 greeting already received\r\n"), conn)}
}

type prefixedConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

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
// github.com/emersion/go-smtp@v0.24.0/client.go), and startTLS does the
// same per step of its pre-TLS greet+EHLO+STARTTLS exchange. A
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
