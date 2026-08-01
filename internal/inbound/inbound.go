// Package inbound is doevoe's SMTP receiver for DMARC aggregate reports.
// It is deliberately not a mail server: it accepts mail for exactly one
// address (dmarc@<system-domain>), never relays, and needs no auth. Every
// accepted message is parsed and stored synchronously in Data(), so a 250
// reply means the report is durably in SQLite (or was a knowingly-dropped
// malformed/duplicate one).
package inbound

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-smtp"

	"doevoe/internal/dmarcreport"
	"doevoe/internal/store"
)

const (
	maxMessageBytes = 15 << 20
	ioTimeout       = 2 * time.Minute
)

type Server struct {
	Store      *store.Store
	ReportAddr string // the only RCPT we accept, e.g. "dmarc@sys.example"
	EgressIP   string // our own sending IP, for the own-failure alert
	Hostname   string // EHLO banner domain
	// OnOwnFailure fires when a stored report shows EgressIP failing both
	// DKIM and SPF — wired to notify.DMARCFailure (which owns the cooldown).
	OnOwnFailure func(domain string, count int)
}

// Serve serves SMTP on l until ctx is cancelled, then shuts down gracefully.
// The caller owns the listener: main.go binds at startup (so a bind failure
// exits like any other misconfiguration), tests bind 127.0.0.1:0.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	srv := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		return &session{srv: s}, nil
	}))
	srv.Domain = s.Hostname
	srv.MaxMessageBytes = maxMessageBytes
	srv.ReadTimeout = ioTimeout
	srv.WriteTimeout = ioTimeout

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(l) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
		srv.Close()
		<-errCh
		return nil
	case err := <-errCh:
		return err
	}
}

type session struct {
	srv *Server
}

func (se *session) Reset()        {}
func (se *session) Logout() error { return nil }

func (se *session) Mail(from string, opts *smtp.MailOptions) error { return nil }

func (se *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	// The one gate that keeps this from being an open relay or a general
	// mailbox: only the report address exists, everything else is 550.
	if !strings.EqualFold(strings.TrimSpace(to), se.srv.ReportAddr) {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "no such user"}
	}
	return nil
}

func (se *session) Data(r io.Reader) error {
	// One bad message must not kill the connection handler.
	defer func() {
		if p := recover(); p != nil {
			slog.Error("inbound: panic handling report", "panic", p)
		}
	}()
	xmlBytes, err := dmarcreport.FromEmail(r)
	if err != nil {
		// Malformed (no payload / bomb / broken MIME): accept and drop.
		// A 5xx would only make the reporter retry a message that will
		// never parse; the raw isn't stored because there's nothing to key
		// it under.
		slog.Warn("inbound: dropping unparsable report message", "err", err)
		return nil
	}
	rep, err := dmarcreport.Parse(strings.NewReader(string(xmlBytes)))
	if err != nil {
		slog.Warn("inbound: dropping malformed report xml", "err", err)
		return nil
	}
	storeRep := &store.DMARCReport{
		Org: rep.Org, ReportID: rep.ReportID, Domain: rep.Domain,
		RangeBegin: store.FmtTime(rep.RangeBegin), RangeEnd: store.FmtTime(rep.RangeEnd),
		ReceivedAt: store.Now(), Raw: string(xmlBytes),
	}
	var recs []store.DMARCRecord
	ownFailures := 0
	for _, r := range rep.Records {
		recs = append(recs, store.DMARCRecord{
			SourceIP: r.SourceIP, Count: int64(r.Count), Disposition: r.Disposition,
			DKIM: r.DKIM, SPF: r.SPF, HeaderFrom: r.HeaderFrom,
		})
		// Both evaluations failing from our own IP is the "our signing or
		// DNS broke" signal; spoofing from other IPs stays page-only.
		if r.SourceIP == se.srv.EgressIP && r.DKIM == "fail" && r.SPF == "fail" {
			ownFailures += r.Count
		}
	}
	_, duplicate, err := se.srv.Store.InsertDMARCReport(storeRep, recs)
	if err != nil {
		// A store error is transient (disk, lock): 451 so the reporter
		// retries later instead of losing the report.
		slog.Error("inbound: storing report failed", "org", rep.Org, "report_id", rep.ReportID, "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "temporary storage failure"}
	}
	if duplicate {
		slog.Info("inbound: duplicate report dropped", "org", rep.Org, "report_id", rep.ReportID)
		return nil
	}
	slog.Info("inbound: stored dmarc report", "org", rep.Org, "domain", rep.Domain, "records", len(recs))
	if ownFailures > 0 && se.srv.OnOwnFailure != nil {
		se.srv.OnOwnFailure(rep.Domain, ownFailures)
	}
	return nil
}
