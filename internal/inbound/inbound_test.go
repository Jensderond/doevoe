package inbound

import (
	"context"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"doevoe/internal/store"
)

// deliver connects to addr and submits one message; returns the error from
// the first failing SMTP step so tests can assert on rejections.
func deliver(t *testing.T, addr, rcpt, msg string) error {
	t.Helper()
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Mail("reporter@google.com", nil); err != nil {
		return err
	}
	if err := c.Rcpt(rcpt, nil); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	return w.Close()
}

func startServer(t *testing.T) (*store.Store, string, *[]struct {
	Domain string
	Count  int
}) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	var alerts []struct {
		Domain string
		Count  int
	}
	srv := &Server{
		Store: s, ReportAddr: "dmarc@sys.example", EgressIP: "203.0.113.7",
		Hostname: "mail.sys.example",
		OnOwnFailure: func(domain string, count int) {
			alerts = append(alerts, struct {
				Domain string
				Count  int
			}{domain, count})
		},
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, l); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	})
	return s, l.Addr().String(), &alerts
}

// reportMsg builds a single-part bare-XML report message (the simplest valid
// shape — extraction of gzip/zip is covered by dmarcreport's own tests).
func reportMsg(reportID, sourceIP, dkim, spf string, count int) string {
	xml := `<feedback><report_metadata><org_name>google.com</org_name><report_id>` + reportID + `</report_id><date_range><begin>1753999200</begin><end>1754085600</end></date_range></report_metadata><policy_published><domain>client.example</domain></policy_published><record><row><source_ip>` + sourceIP + `</source_ip><count>` + strconv.Itoa(count) + `</count><policy_evaluated><disposition>none</disposition><dkim>` + dkim + `</dkim><spf>` + spf + `</spf></policy_evaluated></row><identifiers><header_from>client.example</header_from></identifiers></record></feedback>`
	return "From: reporter@google.com\r\nTo: dmarc@sys.example\r\nSubject: report\r\nMIME-Version: 1.0\r\nContent-Type: application/xml\r\n\r\n" + xml
}

// twoRecordReportMsg builds a report with two <record> rows, both fail/fail,
// so the own-failure count-summing behavior (across records, not just the
// first) can be tested.
func twoRecordReportMsg(reportID, ip1 string, count1 int, ip2 string, count2 int) string {
	rec := func(ip string, count int) string {
		return `<record><row><source_ip>` + ip + `</source_ip><count>` + strconv.Itoa(count) + `</count><policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row><identifiers><header_from>client.example</header_from></identifiers></record>`
	}
	xml := `<feedback><report_metadata><org_name>google.com</org_name><report_id>` + reportID + `</report_id><date_range><begin>1753999200</begin><end>1754085600</end></date_range></report_metadata><policy_published><domain>client.example</domain></policy_published>` +
		rec(ip1, count1) + rec(ip2, count2) + `</feedback>`
	return "From: reporter@google.com\r\nTo: dmarc@sys.example\r\nSubject: report\r\nMIME-Version: 1.0\r\nContent-Type: application/xml\r\n\r\n" + xml
}

// seedVerifiedDomain creates and fully verifies a domain in s, standing in
// for the domain-management flow that runs before a domain can legitimately
// send (and thus before a genuine own-failure report can concern it).
func seedVerifiedDomain(t *testing.T, s *store.Store, name string) {
	t.Helper()
	d, err := s.CreateDomain(name, "mail1", "PEM")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetDomainVerification(d.ID, true, true, true, store.Now()); err != nil {
		t.Fatal(err)
	}
}

// Data() stores synchronously before replying 250, so a returned deliver()
// means the report is already in (or knowingly dropped from) the store — no
// polling needed.
func mustCount(t *testing.T, s *store.Store, want int64) {
	t.Helper()
	n, err := s.CountDMARCReports()
	if err != nil {
		t.Fatal(err)
	}
	if n != want {
		t.Fatalf("stored reports: %d, want %d", n, want)
	}
}

func TestReceiveStoresReport(t *testing.T) {
	s, addr, _ := startServer(t)
	if err := deliver(t, addr, "dmarc@sys.example", reportMsg("rid-1", "198.51.100.9", "fail", "fail", 3)); err != nil {
		t.Fatal(err)
	}
	mustCount(t, s, 1)
}

func TestRcptRejectsNonReportAddress(t *testing.T) {
	_, addr, _ := startServer(t)
	err := deliver(t, addr, "someone@else.example", reportMsg("rid-2", "1.2.3.4", "pass", "pass", 1))
	if err == nil || !strings.Contains(err.Error(), "550") {
		t.Fatalf("want 550 rejection, got %v", err)
	}
}

func TestMalformedAcceptedAndDropped(t *testing.T) {
	s, addr, _ := startServer(t)
	msg := "From: a@b\r\nContent-Type: text/plain\r\n\r\nnot a report"
	if err := deliver(t, addr, "dmarc@sys.example", msg); err != nil {
		t.Fatalf("malformed report must be accepted at SMTP level, got %v", err)
	}
	mustCount(t, s, 0)
}

func TestDuplicateAccepted(t *testing.T) {
	s, addr, _ := startServer(t)
	msg := reportMsg("rid-dup", "1.2.3.4", "pass", "pass", 1)
	if err := deliver(t, addr, "dmarc@sys.example", msg); err != nil {
		t.Fatal(err)
	}
	if err := deliver(t, addr, "dmarc@sys.example", msg); err != nil {
		t.Fatalf("duplicate must be accepted (250), got %v", err)
	}
	mustCount(t, s, 1)
}

func TestOwnFailureTriggersCallback(t *testing.T) {
	s, addr, alerts := startServer(t)
	seedVerifiedDomain(t, s, "client.example")
	// Source IP == EgressIP, both dkim and spf fail, domain is a verified
	// managed domain → callback.
	if err := deliver(t, addr, "dmarc@sys.example", reportMsg("rid-own", "203.0.113.7", "fail", "fail", 14)); err != nil {
		t.Fatal(err)
	}
	if len(*alerts) != 1 || (*alerts)[0].Domain != "client.example" || (*alerts)[0].Count != 14 {
		t.Fatalf("alerts: %+v", *alerts)
	}
}

func TestOtherIPFailureNoCallback(t *testing.T) {
	s, addr, alerts := startServer(t)
	if err := deliver(t, addr, "dmarc@sys.example", reportMsg("rid-spoof", "198.51.100.9", "fail", "fail", 9)); err != nil {
		t.Fatal(err)
	}
	mustCount(t, s, 1)
	if len(*alerts) != 0 {
		t.Fatalf("spoofing by other IPs must not alert: %+v", *alerts)
	}
}

// TestOwnFailureUnmanagedDomainNoCallback is the anti-flooding regression:
// EgressIP is public (it's in every domain's published SPF record), and
// reports are attacker-supplied with an attacker-chosen policy_published
// domain. Without gating on a known, verified domain, an attacker could mint
// unlimited unique forged domains — each dodging notify's per-domain
// cooldown — and flood the admin mailbox. Here client.example is never
// created in the store, so even a report claiming an own-IP double failure
// must store fine but must NOT alert.
func TestOwnFailureUnmanagedDomainNoCallback(t *testing.T) {
	s, addr, alerts := startServer(t)
	if err := deliver(t, addr, "dmarc@sys.example", reportMsg("rid-unmanaged", "203.0.113.7", "fail", "fail", 5)); err != nil {
		t.Fatal(err)
	}
	mustCount(t, s, 1)
	if len(*alerts) != 0 {
		t.Fatalf("unmanaged domain must not alert: %+v", *alerts)
	}
}

// TestOwnFailureSumsAcrossRecords checks ownFailures accumulates over every
// matching record in the report, not just the first.
func TestOwnFailureSumsAcrossRecords(t *testing.T) {
	s, addr, alerts := startServer(t)
	seedVerifiedDomain(t, s, "client.example")
	msg := twoRecordReportMsg("rid-multi", "203.0.113.7", 3, "203.0.113.7", 4)
	if err := deliver(t, addr, "dmarc@sys.example", msg); err != nil {
		t.Fatal(err)
	}
	mustCount(t, s, 1)
	if len(*alerts) != 1 || (*alerts)[0].Count != 7 {
		t.Fatalf("alerts: %+v, want single alert with count 7", *alerts)
	}
}

// TestOversizeMessageRejected: a message well over maxMessageBytes must
// never end up stored — either go-smtp's own MaxMessageBytes/line-length
// enforcement rejects it outright (surfacing as an error on Data, the
// client's write, or its close), or, if the SMTP layer lets it through,
// dmarcreport's own size cap makes it unparsable and it gets dropped. Either
// way, nothing should be stored.
func TestOversizeMessageRejected(t *testing.T) {
	s, addr, _ := startServer(t)
	filler := strings.Repeat("A", maxMessageBytes+(1<<20))
	msg := "From: reporter@google.com\r\nTo: dmarc@sys.example\r\nSubject: report\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\n" + filler
	if err := deliver(t, addr, "dmarc@sys.example", msg); err == nil {
		t.Fatal("expected oversize message to be rejected")
	}
	mustCount(t, s, 0)
}
