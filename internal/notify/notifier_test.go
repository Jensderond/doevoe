package notify

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"doevoe/internal/store"
)

func fixture(t *testing.T, systemVerified bool) (*store.Store, *Notifier, int64) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	sys, _ := s.CreateDomain("sys.example", "mail1", "PEM")
	if systemVerified {
		s.SetDomainVerification(sys.ID, true, true, true, store.Now())
	}
	client, _ := s.CreateDomain("client.example", "mail1", "PEM")
	n := &Notifier{Store: s, AdminEmail: "ops@example.com", SystemFrom: "noreply@sys.example",
		BaseURL: "https://doevoe.example", Threshold: 0.2, MinVolume: 10}
	return s, n, client.ID
}

func systemEmails(t *testing.T, s *store.Store) []*store.Email {
	t.Helper()
	all, err := s.ListEmails(store.EmailFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []*store.Email
	for _, e := range all {
		if e.IsSystem {
			out = append(out, e)
		}
	}
	return out
}

func failEmail(t *testing.T, s *store.Store, domainID int64, to string) int64 {
	t.Helper()
	id, _ := s.EnqueueEmail(&store.Email{DomainID: domainID, From: "a@client.example", To: to, Subject: "s", BodyText: "b"})
	s.MarkFailed(id, "550 no such user")
	return id
}

func TestDigestBatchesWithCooldown(t *testing.T) {
	s, n, clientID := fixture(t, true)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	n.PermanentFailure(failEmail(t, s, clientID, "a@dest.test"))
	n.PermanentFailure(failEmail(t, s, clientID, "b@dest.test"))
	if err := n.DigestTick(now); err != nil {
		t.Fatal(err)
	}
	if got := systemEmails(t, s); len(got) != 1 {
		t.Fatalf("want 1 digest, got %d", len(got))
	}
	if pending, _ := s.ListPendingFailures(); len(pending) != 0 {
		t.Fatal("pending must be cleared after digest")
	}

	n.PermanentFailure(failEmail(t, s, clientID, "c@dest.test"))
	n.DigestTick(now.Add(5 * time.Minute)) // inside cooldown
	if got := systemEmails(t, s); len(got) != 1 {
		t.Fatal("cooldown violated")
	}
	n.DigestTick(now.Add(2 * time.Hour))
	if got := systemEmails(t, s); len(got) != 2 {
		t.Fatal("second digest expected after cooldown")
	}
}

func TestDigestSkipsWhenSystemDomainUnverified(t *testing.T) {
	s, n, clientID := fixture(t, false)
	n.PermanentFailure(failEmail(t, s, clientID, "a@dest.test"))
	if err := n.DigestTick(time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := systemEmails(t, s); len(got) != 0 {
		t.Fatal("must not enqueue via unverified system domain")
	}
	if pending, _ := s.ListPendingFailures(); len(pending) != 1 {
		t.Fatal("pending must be kept for later")
	}
}

func TestSystemFailuresNeverNotify(t *testing.T) {
	s, n, _ := fixture(t, true)
	sys, _ := s.GetDomainByName("sys.example")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: sys.ID, From: "noreply@sys.example",
		To: "ops@example.com", Subject: "alert", BodyText: "b", IsSystem: true})
	s.MarkFailed(id, "451")
	n.PermanentFailure(id)
	if pending, _ := s.ListPendingFailures(); len(pending) != 0 {
		t.Fatal("system email failure must not create pending notification (loop guard)")
	}
}

func TestRateAlertFiresOncePerIncident(t *testing.T) {
	s, n, clientID := fixture(t, true)
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		id := failEmail(t, s, clientID, "x@dest.test")
		code := 250
		if i < 5 {
			code = 451
		}
		s.RecordAttempt(id, 1, code, "mx", "resp", 10)
	}
	n.RateTick(now)
	n.RateTick(now)
	if got := systemEmails(t, s); len(got) != 1 {
		t.Fatalf("want exactly 1 rate alert, got %d", len(got))
	}
}

func TestRateAlertContinuesAfterFiredDomain(t *testing.T) {
	s, n, clientID := fixture(t, true)
	now := time.Now().UTC()

	// Create second domain to test per-domain isolation
	domain2, _ := s.CreateDomain("client2.example", "mail1", "PEM")
	s.SetDomainVerification(domain2.ID, true, true, true, store.Now())

	// Both domains: 10 attempts, 5 failures (50% >= 20% threshold), >= 10 min volume
	for i := 0; i < 10; i++ {
		id1 := failEmail(t, s, clientID, "x@dest.test")
		code := 250
		if i < 5 {
			code = 451
		}
		s.RecordAttempt(id1, 1, code, "mx", "resp", 10)

		id2 := failEmail(t, s, domain2.ID, "x@dest.test")
		s.RecordAttempt(id2, 1, code, "mx", "resp", 10)
	}

	// Pre-fire domain1 (client.example) so it skips alert in this tick
	s.SetState("rate_fired_client.example", "fired")

	// Run RateTick: domain1 should skip (already fired), domain2 should fire
	if err := n.RateTick(now); err != nil {
		t.Fatal(err)
	}

	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 rate alert (domain2 only), got %d", len(got))
	}
	if !strings.Contains(got[0].Subject, "client2.example") {
		t.Fatalf("want alert for client2.example, got subject: %q", got[0].Subject)
	}
}

func TestRateAlertContinuesAfterErroringDomain(t *testing.T) {
	s, n, d1ID := fixture(t, true)
	now := time.Now().UTC()

	// Create second domain to test per-domain error isolation
	d2, _ := s.CreateDomain("client2.example", "mail1", "PEM")
	d2ID := d2.ID
	s.SetDomainVerification(d2ID, true, true, true, store.Now())

	// Both domains: 10 attempts, 5 failures (50% >= 20% threshold), >= 10 min volume
	for i := 0; i < 10; i++ {
		id1 := failEmail(t, s, d1ID, "x@dest.test")
		code := 250
		if i < 5 {
			code = 451
		}
		s.RecordAttempt(id1, 1, code, "mx", "resp", 10)

		id2 := failEmail(t, s, d2ID, "x@dest.test")
		s.RecordAttempt(id2, 1, code, "mx", "resp", 10)
	}

	// Inject error for d1, but delegate to store for d2
	n.failureRateFn = func(domainID int64, since string) (failed, total int, err error) {
		if domainID == d1ID {
			return 0, 0, fmt.Errorf("injected d1 error")
		}
		return s.FailureRate(domainID, since)
	}

	// Run RateTick: d1 should error and continue, d2 should still fire
	err := n.RateTick(now)
	if err == nil {
		t.Fatal("want RateTick to return firstErr from d1")
	}
	if !strings.Contains(err.Error(), "injected d1 error") {
		t.Fatalf("want error containing 'injected d1 error', got: %v", err)
	}

	// Verify d2 still fired despite d1's error
	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 rate alert (d2 only), got %d", len(got))
	}
	if !strings.Contains(got[0].Subject, "client2.example") {
		t.Fatalf("want alert for client2.example, got subject: %q", got[0].Subject)
	}

	// Verify state: d2 fired, d1 not set
	if state, _ := s.GetState("rate_fired_client2.example"); state != "fired" {
		t.Fatalf("want rate_fired_client2.example to be 'fired', got: %q", state)
	}
	if state, _ := s.GetState("rate_fired_client.example"); state != "" {
		t.Fatalf("want rate_fired_client.example to be empty, got: %q", state)
	}
}

func TestMonthlyStats(t *testing.T) {
	s, n, clientID := fixture(t, true)
	jul := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)

	// fresh install: initialize, don't send
	n.StatsTick(jul)
	if got := systemEmails(t, s); len(got) != 0 {
		t.Fatal("no phantom report on fresh install")
	}
	// activity in July
	id := failEmail(t, s, clientID, "x@dest.test")
	_ = id
	// month rolls over
	aug := time.Date(2026, 8, 1, 0, 30, 0, 0, time.UTC)
	n.StatsTick(aug)
	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want stats email, got %d", len(got))
	}
	if v, _ := s.GetState("last_stats_sent"); v != "2026-08" {
		t.Fatalf("state: %q", v)
	}
	n.StatsTick(aug.Add(time.Hour))
	if got := systemEmails(t, s); len(got) != 1 {
		t.Fatal("stats must send once per month")
	}
}

// emailInMonth creates an email with created_at inside the given month and
// marks it sent or failed.
func emailInMonth(t *testing.T, s *store.Store, domainID int64, month string, sent bool) {
	t.Helper()
	id, err := s.EnqueueEmail(&store.Email{DomainID: domainID, From: "a@client.example",
		To: "u@dest.test", Subject: "s", BodyText: "b", CreatedAt: month + "-15T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if sent {
		s.MarkSent(id, month+"-15T12:00:01Z")
	} else {
		s.MarkFailed(id, "550 no such user")
	}
}

func TestMonthlyStatsComparesToPreviousMonth(t *testing.T) {
	s, n, clientID := fixture(t, true)
	s.SetState("last_stats_sent", "2026-07")

	// June: 1 sent, 1 failed (50%). July: 2 sent, 0 failed (100%).
	emailInMonth(t, s, clientID, "2026-06", true)
	emailInMonth(t, s, clientID, "2026-06", false)
	emailInMonth(t, s, clientID, "2026-07", true)
	emailInMonth(t, s, clientID, "2026-07", true)

	if err := n.StatsTick(time.Date(2026, 8, 1, 0, 30, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want 1 stats email, got %d", len(got))
	}
	body := got[0].BodyText
	for _, want := range []string{
		"2 sent, 0 failed (100.0% delivered)",
		"prev month: 1 sent, 1 failed (50.0% delivered)",
		"+50.0pt",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("stats body missing %q:\n%s", want, body)
		}
	}
}

func TestMonthlyStatsComparisonNoPriorActivity(t *testing.T) {
	s, n, clientID := fixture(t, true)
	s.SetState("last_stats_sent", "2026-07")
	emailInMonth(t, s, clientID, "2026-07", true)

	if err := n.StatsTick(time.Date(2026, 8, 1, 0, 30, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want 1 stats email, got %d", len(got))
	}
	if !strings.Contains(got[0].BodyText, "prev month: no activity") {
		t.Errorf("stats body should note missing prior activity:\n%s", got[0].BodyText)
	}
}

func TestMonthlyStatsComparisonDomainWentQuiet(t *testing.T) {
	s, n, clientID := fixture(t, true)
	s.SetState("last_stats_sent", "2026-07")
	// Activity in June only; nothing in July.
	emailInMonth(t, s, clientID, "2026-06", true)

	if err := n.StatsTick(time.Date(2026, 8, 1, 0, 30, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want 1 stats email, got %d", len(got))
	}
	body := got[0].BodyText
	if !strings.Contains(body, "client.example: no activity") ||
		!strings.Contains(body, "prev month: 1 sent, 0 failed (100.0% delivered)") {
		t.Errorf("domain that went quiet should still appear with its prior numbers:\n%s", body)
	}
}

func TestMonthlyStatsAcrossMonthBoundary(t *testing.T) {
	s, n, _ := fixture(t, true)

	if err := s.SetState("last_stats_sent", "2026-07"); err != nil {
		t.Fatal(err)
	}
	tick := time.Date(2026, 8, 31, 9, 0, 0, 0, time.UTC)

	if err := n.StatsTick(tick); err != nil {
		t.Fatal(err)
	}

	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want 1 stats email, got %d", len(got))
	}
	if !strings.Contains(got[0].Subject, "2026-07") && !strings.Contains(got[0].BodyText, "2026-07") {
		t.Fatalf("want stats for previous month 2026-07, subject=%q body=%q", got[0].Subject, got[0].BodyText)
	}
	if v, _ := s.GetState("last_stats_sent"); v != "2026-08" {
		t.Fatalf("state: %q", v)
	}
}

func TestMonthlyStatsHandlesMonthEndOverflow(t *testing.T) {
	// Regression test for the previous-month calculation bug: naively doing
	// now.AddDate(0, -1, 0) on a day that doesn't exist in the shorter
	// previous month (e.g. 2026-03-31 minus 1 month has no Feb 31) overflows
	// forward and resolves back to "2026-03" instead of "2026-02",
	// permanently skipping the real previous month. StatsTick must normalize
	// to the first of the month before subtracting.
	s, n, _ := fixture(t, true)

	if err := s.SetState("last_stats_sent", "2026-02"); err != nil {
		t.Fatal(err)
	}
	tick := time.Date(2026, 3, 31, 9, 0, 0, 0, time.UTC)

	if err := n.StatsTick(tick); err != nil {
		t.Fatal(err)
	}

	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want 1 stats email, got %d", len(got))
	}
	if !strings.Contains(got[0].Subject, "2026-02") && !strings.Contains(got[0].BodyText, "2026-02") {
		t.Fatalf("want stats for previous month 2026-02, subject=%q body=%q", got[0].Subject, got[0].BodyText)
	}
	if v, _ := s.GetState("last_stats_sent"); v != "2026-03" {
		t.Fatalf("state: %q", v)
	}
}

func TestMonthlyStatsHTMLBody(t *testing.T) {
	s, n, clientID := fixture(t, true)
	s.SetState("last_stats_sent", "2026-07")

	// June: 1 sent, 1 failed. July: 2 sent, 1 failed — the failure carries
	// HTML metacharacters, which must come out escaped in the HTML body
	// (SMTP error text is remote-server-controlled).
	emailInMonth(t, s, clientID, "2026-06", true)
	emailInMonth(t, s, clientID, "2026-06", false)
	emailInMonth(t, s, clientID, "2026-07", true)
	emailInMonth(t, s, clientID, "2026-07", true)
	id, err := s.EnqueueEmail(&store.Email{DomainID: clientID, From: "a@client.example",
		To: "u@dest.test", Subject: "s", BodyText: "b", CreatedAt: "2026-07-15T12:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	s.MarkFailed(id, `550 <blocked> & "rejected"`)

	if err := n.StatsTick(time.Date(2026, 8, 1, 0, 30, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want 1 stats email, got %d", len(got))
	}
	html := got[0].BodyHTML
	if html == "" {
		t.Fatal("stats email must carry an HTML alternative body")
	}
	for _, want := range []string{
		"July 2026",       // month heading
		"client.example",  // per-domain row
		"66.7%",           // July delivery rate (2 sent, 1 failed)
		"&#43;16.7pt",     // delta vs June's 50.0% (html/template escapes the +)
		"sys.example",     // DNS verification section lists all domains
		n.BaseURL + "/admin/",
		"550 &lt;blocked&gt; &amp; &#34;rejected&#34;", // escaped failure reason
	} {
		if !strings.Contains(html, want) {
			t.Errorf("stats HTML missing %q:\n%s", want, html)
		}
	}
	if strings.Contains(html, "550 <blocked>") {
		t.Error("failure reason rendered unescaped into HTML")
	}
	// The HTML body is written to the wire verbatim (no quoted-printable),
	// so every line must stay under SMTP's 998-byte limit.
	for i, line := range strings.Split(html, "\n") {
		if len(line) > 900 {
			t.Errorf("HTML line %d is %d bytes, too close to the 998-byte SMTP limit", i+1, len(line))
		}
	}
}

func TestMonthlyStatsHTMLQuietAndUnverified(t *testing.T) {
	s, n, clientID := fixture(t, true)
	s.SetState("last_stats_sent", "2026-07")
	// Activity in June only: client.example must appear as "no activity",
	// and being unverified it must show as blocked in the DNS section.
	emailInMonth(t, s, clientID, "2026-06", true)

	if err := n.StatsTick(time.Date(2026, 8, 1, 0, 30, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want 1 stats email, got %d", len(got))
	}
	html := got[0].BodyHTML
	for _, want := range []string{
		"no activity",
		"1 sent, 0 failed (100.0% delivered)", // June counts in the prev column
		"NOT VERIFIED",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("stats HTML missing %q:\n%s", want, html)
		}
	}
}

func TestNonStatsNotificationsStayTextOnly(t *testing.T) {
	s, n, _ := fixture(t, true)
	n.KeyCreated("deploy", "client.example")
	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want 1 email, got %d", len(got))
	}
	if got[0].BodyHTML != "" {
		t.Errorf("key-created notification should be text-only, got HTML: %q", got[0].BodyHTML)
	}
}

func TestBlocklistNotifications(t *testing.T) {
	s, n, _ := fixture(t, true)

	n.BlocklistHit("203.0.113.7", "zen.spamhaus.org")
	emails := systemEmails(t, s)
	if len(emails) != 1 {
		t.Fatalf("after hit: %d system emails, want 1", len(emails))
	}
	if !strings.Contains(emails[0].Subject, "zen.spamhaus.org") ||
		!strings.Contains(emails[0].BodyText, "203.0.113.7") {
		t.Errorf("hit email lacks zone/target: subject=%q body=%q", emails[0].Subject, emails[0].BodyText)
	}

	n.BlocklistCleared("203.0.113.7", "zen.spamhaus.org")
	emails = systemEmails(t, s)
	if len(emails) != 2 {
		t.Fatalf("after clear: %d system emails, want 2", len(emails))
	}
}

func TestBlocklistNotificationsFailOpenUnverified(t *testing.T) {
	s, n, _ := fixture(t, false) // system domain not verified
	n.BlocklistHit("203.0.113.7", "zen.spamhaus.org")
	if got := len(systemEmails(t, s)); got != 0 {
		t.Fatalf("unverified system domain must skip silently, got %d emails", got)
	}
}

func TestDMARCFailureCooldown(t *testing.T) {
	s, n, _ := fixture(t, true)

	n.DMARCFailure("client.example", 14)
	emails := systemEmails(t, s)
	if len(emails) != 1 {
		t.Fatalf("first alert: %d system emails, want 1", len(emails))
	}
	if !strings.Contains(emails[0].Subject, "client.example") ||
		!strings.Contains(emails[0].BodyText, "14") {
		t.Errorf("alert lacks domain/count: subject=%q body=%q", emails[0].Subject, emails[0].BodyText)
	}

	// Within the cooldown: silent.
	n.DMARCFailure("client.example", 5)
	if got := len(systemEmails(t, s)); got != 1 {
		t.Fatalf("cooldown violated: %d emails, want 1", got)
	}

	// A different domain has its own cooldown.
	n.DMARCFailure("other.example", 2)
	if got := len(systemEmails(t, s)); got != 2 {
		t.Fatalf("per-domain cooldown: %d emails, want 2", got)
	}

	// Cooldown expired: fires again.
	s.SetState("dmarc_alert_client.example", store.FmtTime(time.Now().UTC().Add(-25*time.Hour)))
	n.DMARCFailure("client.example", 7)
	if got := len(systemEmails(t, s)); got != 3 {
		t.Fatalf("after expiry: %d emails, want 3", got)
	}
}

func TestDMARCFailureFailOpenUnverified(t *testing.T) {
	s, n, _ := fixture(t, false)
	n.DMARCFailure("client.example", 3)
	if got := len(systemEmails(t, s)); got != 0 {
		t.Fatalf("unverified system domain must skip silently, got %d", got)
	}
	// A skipped send must NOT start the cooldown — otherwise verifying the
	// system domain within 24h of a failure silently swallows the alert.
	if v, _ := s.GetState("dmarc_alert_client.example"); v != "" {
		t.Fatalf("cooldown set despite skipped send: %q", v)
	}
}
