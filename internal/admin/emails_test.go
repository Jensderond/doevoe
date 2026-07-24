package admin

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"doevoe/internal/store"
)

func TestEmailsListAndFilter(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@gmial.com", Subject: "Welcome!", BodyText: "hi"})
	s.MarkFailed(id, "550 no such domain")

	resp, _ := c.Get(srv.URL + "/admin/emails?status=failed")
	body := readBody(t, resp)
	if !strings.Contains(body, "u@gmial.com") || !strings.Contains(body, "Welcome!") {
		t.Fatalf("failed email missing from list:\n%s", body)
	}
	resp, _ = c.Get(srv.URL + "/admin/emails?status=sent")
	if strings.Contains(readBody(t, resp), "u@gmial.com") {
		t.Fatal("status filter not applied")
	}
}

func TestEmailDetailShowsAttempts(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@dest.test", Subject: "s", BodyText: "b"})
	s.RecordAttempt(id, 1, 451, "mx1.dest.test", "451 greylisted, try later", 320)

	resp, _ := c.Get(srv.URL + "/admin/emails/1")
	body := readBody(t, resp)
	for _, want := range []string{"mx1.dest.test", "451 greylisted", "u@dest.test"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q", want)
		}
	}
}

func TestRetryWithRecipientEdit(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@gmial.com", Subject: "s", BodyText: "b"})
	s.MarkFailed(id, "550")

	resp, err := c.PostForm(srv.URL+"/admin/emails/1/retry", url.Values{"to": {"u@gmail.com"}})
	if err != nil || resp.StatusCode != 303 {
		t.Fatalf("retry: %v %d", err, resp.StatusCode)
	}
	e, _ := s.GetEmail(id)
	if e.To != "u@gmail.com" || e.OriginalTo != "u@gmial.com" || e.Status != "queued" {
		t.Fatalf("after retry: %+v", e)
	}
}

func TestDomainFilter(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d1, _ := s.CreateDomain("example.com", "mail1", "PEM")
	d2, _ := s.CreateDomain("example.org", "mail2", "PEM")
	id1, _ := s.EnqueueEmail(&store.Email{DomainID: d1.ID, From: "a@example.com", To: "u1@dest.test", Subject: "s1", BodyText: "b"})
	id2, _ := s.EnqueueEmail(&store.Email{DomainID: d2.ID, From: "a@example.org", To: "u2@dest.test", Subject: "s2", BodyText: "b"})
	s.MarkFailed(id1, "550")
	s.MarkFailed(id2, "550")

	// Filter by first domain
	resp, _ := c.Get(srv.URL + "/admin/emails?domain=" + strconv.FormatInt(d1.ID, 10))
	body := readBody(t, resp)
	if !strings.Contains(body, "u1@dest.test") {
		t.Errorf("domain 1 email missing")
	}
	if strings.Contains(body, "u2@dest.test") {
		t.Errorf("domain 2 email should not be shown")
	}

	// Filter by second domain
	resp, _ = c.Get(srv.URL + "/admin/emails?domain=" + strconv.FormatInt(d2.ID, 10))
	body = readBody(t, resp)
	if !strings.Contains(body, "u2@dest.test") {
		t.Errorf("domain 2 email missing")
	}
	if strings.Contains(body, "u1@dest.test") {
		t.Errorf("domain 1 email should not be shown")
	}
}

func TestSearchEmails(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	_, _ = s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "alice@example.com", Subject: "Hello", BodyText: "b"})
	_, _ = s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "bob@example.com", Subject: "World", BodyText: "b"})

	// Search matching alice
	resp, _ := c.Get(srv.URL + "/admin/emails?q=alice")
	body := readBody(t, resp)
	if !strings.Contains(body, "alice@example.com") {
		t.Errorf("alice email missing from search results")
	}
	if strings.Contains(body, "bob@example.com") {
		t.Errorf("bob email should not be in alice search")
	}

	// Search non-matching
	resp, _ = c.Get(srv.URL + "/admin/emails?q=charlie")
	body = readBody(t, resp)
	if strings.Contains(body, "alice@example.com") || strings.Contains(body, "bob@example.com") {
		t.Errorf("non-matching search should show neither email")
	}
}

func TestDateRangeFilter(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	for day, to := range map[string]string{
		"2026-07-01T10:00:00Z": "early@dest.test",
		"2026-07-10T10:00:00Z": "mid@dest.test",
		"2026-07-20T10:00:00Z": "late@dest.test",
	} {
		s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: to, Subject: "s", BodyText: "b", CreatedAt: day})
	}

	// A bare from/to pair (no range param) still means a custom range, so
	// links bookmarked before the period chips existed keep working.
	resp, _ := c.Get(srv.URL + "/admin/emails?from=2026-07-05&to=2026-07-10")
	body := readBody(t, resp)
	if !strings.Contains(body, "mid@dest.test") {
		t.Errorf("email on the inclusive 'to' day missing:\n%s", body)
	}
	if strings.Contains(body, "early@dest.test") || strings.Contains(body, "late@dest.test") {
		t.Error("emails outside the date range should not be shown")
	}

	// The submitted values must round-trip into the form inputs, with the
	// Custom chip selected so they visibly apply.
	if !strings.Contains(body, `value="2026-07-05"`) || !strings.Contains(body, `value="2026-07-10"`) {
		t.Error("date inputs should retain the submitted values")
	}
	if !strings.Contains(body, `value="custom" checked`) {
		t.Errorf("dates should select the Custom period chip:\n%s", body)
	}

	// The same window picked explicitly via the Custom chip.
	resp, _ = c.Get(srv.URL + "/admin/emails?range=custom&from=2026-07-05&to=2026-07-10")
	if body = readBody(t, resp); !strings.Contains(body, "mid@dest.test") ||
		strings.Contains(body, "early@dest.test") {
		t.Errorf("range=custom should use the submitted dates:\n%s", body)
	}

	// Unparseable dates don't error; with no usable bound left, the list falls
	// back to its default window rather than scanning everything.
	resp, _ = c.Get(srv.URL + "/admin/emails?from=banana&to=2026-13-99")
	body = readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("invalid dates should be ignored, got status %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Last 7 days") {
		t.Errorf("invalid dates should fall back to the default window:\n%s", body)
	}
}

// The list opens on recent mail: no filter params means the last 7 days, and
// the period chips are how you widen or narrow that.
func TestDefaultAndPresetRanges(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	now := time.Now().UTC()
	for to, age := range map[string]time.Duration{
		"fresh@dest.test":  2 * time.Hour,
		"recent@dest.test": 3 * 24 * time.Hour,
		"stale@dest.test":  40 * 24 * time.Hour,
	} {
		s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: to,
			Subject: "s", BodyText: "b", CreatedAt: store.FmtTime(now.Add(-age))})
	}

	// Default: last 7 days, and the page says so.
	body := getBody(t, c, srv.URL+"/admin/emails")
	if !strings.Contains(body, "fresh@dest.test") || !strings.Contains(body, "recent@dest.test") {
		t.Errorf("default window should show the last 7 days:\n%s", body)
	}
	if strings.Contains(body, "stale@dest.test") {
		t.Error("default window should not show a 40-day-old email")
	}
	if !strings.Contains(body, "Last 7 days") || !strings.Contains(body, `value="7d" checked`) {
		t.Errorf("default window should be labeled and its chip selected:\n%s", body)
	}

	for _, tc := range []struct {
		query        string
		want, unwant []string
	}{
		{"?range=1d", []string{"fresh@dest.test"}, []string{"recent@dest.test", "stale@dest.test"}},
		{"?range=30d", []string{"fresh@dest.test", "recent@dest.test"}, []string{"stale@dest.test"}},
		{"?range=90d", []string{"fresh@dest.test", "stale@dest.test"}, nil},
		{"?range=all", []string{"fresh@dest.test", "recent@dest.test", "stale@dest.test"}, nil},
		// A preset supersedes leftover dates, and junk falls back to the default.
		{"?range=all&from=2026-07-05&to=2026-07-10", []string{"stale@dest.test"}, nil},
		{"?range=banana", []string{"fresh@dest.test"}, []string{"stale@dest.test"}},
		{"?range=custom", []string{"fresh@dest.test"}, []string{"stale@dest.test"}},
	} {
		body := getBody(t, c, srv.URL+"/admin/emails"+tc.query)
		for _, want := range tc.want {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %s", tc.query, want)
			}
		}
		for _, unwant := range tc.unwant {
			if strings.Contains(body, unwant) {
				t.Errorf("%s: should not show %s", tc.query, unwant)
			}
		}
	}

	// The empty state offers a way out of the window that hid the rows.
	body = getBody(t, c, srv.URL+"/admin/emails?range=1d&q=stale")
	if !strings.Contains(body, "search all time") || !strings.Contains(body, "range=all") {
		t.Errorf("empty state should link to the all-time list:\n%s", body)
	}
}

func getBody(t *testing.T, c *http.Client, rawURL string) string {
	t.Helper()
	resp, err := c.Get(rawURL)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	return readBody(t, resp)
}

func TestPagination(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	// Minutes apart within the default window, so paging is exercised on the
	// list as it opens (u60 newest).
	base := time.Now().UTC().Add(-2 * time.Hour)
	for i := 1; i <= 60; i++ {
		s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com",
			To: fmt.Sprintf("u%02d@dest.test", i), Subject: "s", BodyText: "b",
			CreatedAt: store.FmtTime(base.Add(time.Duration(i) * time.Minute))})
	}

	// Page 1 (default): the 50 newest, with a link to the next page.
	resp, _ := c.Get(srv.URL + "/admin/emails")
	body := readBody(t, resp)
	if !strings.Contains(body, "u60@dest.test") || !strings.Contains(body, "u11@dest.test") {
		t.Error("page 1 should show the 50 newest emails")
	}
	if strings.Contains(body, "u10@dest.test") {
		t.Error("page 1 must not leak page 2 rows")
	}
	if !strings.Contains(body, "page=2") {
		t.Error("page 1 should link to page 2")
	}

	// Page 2: the remaining 10, with a link back but not forward.
	resp, _ = c.Get(srv.URL + "/admin/emails?page=2")
	body = readBody(t, resp)
	if !strings.Contains(body, "u10@dest.test") || !strings.Contains(body, "u01@dest.test") {
		t.Error("page 2 should show the remaining emails")
	}
	if strings.Contains(body, "u11@dest.test") {
		t.Error("page 2 must not repeat page 1 rows")
	}
	if !strings.Contains(body, "page=1") {
		t.Error("page 2 should link back to page 1")
	}
	if strings.Contains(body, "page=3") {
		t.Error("page 2 is the last page and must not link to page 3")
	}

	// Filters, including the active period, are preserved in pagination links.
	resp, _ = c.Get(srv.URL + "/admin/emails?status=queued&q=dest")
	body = readBody(t, resp)
	older := regexpMustFind(t, body, `href="[^"]*page=2[^"]*"`)
	for _, want := range []string{"status=queued", "q=dest", "range=7d"} {
		if !strings.Contains(older, want) {
			t.Errorf("pagination link should preserve %s, got %s", want, older)
		}
	}

	// A custom range travels as its dates, not as a re-derived window.
	from := base.Format("2006-01-02")
	resp, _ = c.Get(srv.URL + "/admin/emails?range=custom&from=" + from)
	older = regexpMustFind(t, readBody(t, resp), `href="[^"]*page=2[^"]*"`)
	if !strings.Contains(older, "range=custom") || !strings.Contains(older, "from="+from) {
		t.Errorf("pagination link should preserve the custom range, got %s", older)
	}

	// Out-of-range and invalid pages degrade gracefully.
	resp, _ = c.Get(srv.URL + "/admin/emails?page=99")
	if body = readBody(t, resp); !strings.Contains(body, "No emails match") {
		t.Error("out-of-range page should render the empty state")
	}
	resp, _ = c.Get(srv.URL + "/admin/emails?page=banana")
	if body = readBody(t, resp); resp.StatusCode != 200 || !strings.Contains(body, "u60@dest.test") {
		t.Error("invalid page should fall back to page 1")
	}
}

func regexpMustFind(t *testing.T, body, pattern string) string {
	t.Helper()
	m := regexp.MustCompile(pattern).FindString(body)
	if m == "" {
		t.Fatalf("no match for %s in body:\n%s", pattern, body)
	}
	return m
}

func TestPlainRetryUnchangedRecipient(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@example.com", Subject: "s", BodyText: "b"})
	s.MarkFailed(id, "550")

	resp, err := c.PostForm(srv.URL+"/admin/emails/"+strconv.FormatInt(id, 10)+"/retry", url.Values{"to": {"u@example.com"}})
	if err != nil || resp.StatusCode != 303 {
		t.Fatalf("plain retry: %v %d", err, resp.StatusCode)
	}
	e, _ := s.GetEmail(id)
	if e.Status != "queued" || e.OriginalTo != "" {
		t.Fatalf("after plain retry: status=%s, original_to=%q", e.Status, e.OriginalTo)
	}
}

func TestRetryInvalidAddress(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@example.com", Subject: "s", BodyText: "b"})
	s.MarkFailed(id, "550")

	resp, _ := c.PostForm(srv.URL+"/admin/emails/"+strconv.FormatInt(id, 10)+"/retry", url.Values{"to": {"not-an-address"}})
	if resp.StatusCode != 422 {
		t.Fatalf("invalid address should return 422, got %d", resp.StatusCode)
	}
	e, _ := s.GetEmail(id)
	if e.Status != "failed" {
		t.Fatalf("email should still be failed after invalid retry attempt")
	}
}

func TestRetryNotFound(t *testing.T) {
	_, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")

	resp, _ := c.PostForm(srv.URL+"/admin/emails/99999/retry", url.Values{})
	if resp.StatusCode != 404 {
		t.Fatalf("POST retry on missing email should return 404, got %d", resp.StatusCode)
	}
}

func TestCancelQueuedEmail(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@dest.test", Subject: "s", BodyText: "b"})
	s.MarkRetry(id, "2099-01-01T00:00:00Z", "dial tcp :25: connect: connection refused")

	// The queued email offers both actions on its detail page.
	resp, _ := c.Get(srv.URL + "/admin/emails/" + strconv.FormatInt(id, 10))
	body := readBody(t, resp)
	for _, want := range []string{"/cancel", "Stop retrying", "/retry"} {
		if !strings.Contains(body, want) {
			t.Errorf("queued email detail missing %q", want)
		}
	}

	resp, err := c.PostForm(srv.URL+"/admin/emails/"+strconv.FormatInt(id, 10)+"/cancel", url.Values{})
	if err != nil || resp.StatusCode != 303 {
		t.Fatalf("cancel: %v %d", err, resp.StatusCode)
	}
	e, _ := s.GetEmail(id)
	if e.Status != "canceled" || e.LastError == "" {
		t.Fatalf("after cancel: %+v", e)
	}

	// A canceled email keeps its retry form (so the recipient can be fixed
	// and delivery resumed) but no longer offers a cancel.
	resp, _ = c.Get(srv.URL + "/admin/emails/" + strconv.FormatInt(id, 10))
	body = readBody(t, resp)
	if !strings.Contains(body, "/retry") {
		t.Error("canceled email should still offer a retry")
	}
	if strings.Contains(body, "Stop retrying") {
		t.Error("canceled email should not offer another cancel")
	}
}

func TestCancelStatusGuardAndNotFound(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@dest.test", Subject: "s", BodyText: "b"})
	s.MarkSent(id, "2026-07-01T00:00:00Z")

	resp, _ := c.PostForm(srv.URL+"/admin/emails/"+strconv.FormatInt(id, 10)+"/cancel", url.Values{})
	if resp.StatusCode != 409 {
		t.Fatalf("cancel on sent email should return 409, got %d", resp.StatusCode)
	}
	if e, _ := s.GetEmail(id); e.Status != "sent" {
		t.Fatalf("email should still be sent, got %s", e.Status)
	}

	resp, _ = c.PostForm(srv.URL+"/admin/emails/99999/cancel", url.Values{})
	if resp.StatusCode != 404 {
		t.Fatalf("cancel on missing email should return 404, got %d", resp.StatusCode)
	}
}

func TestRetryQueuedEmailWithNewRecipient(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@wrong.test", Subject: "s", BodyText: "b"})
	s.MarkRetry(id, "2099-01-01T00:00:00Z", "dial tcp :25: connect: connection refused")

	// Still retrying on a wrong domain: fix the address without waiting out the backoff.
	resp, err := c.PostForm(srv.URL+"/admin/emails/"+strconv.FormatInt(id, 10)+"/retry",
		url.Values{"to": {"u@right.test"}})
	if err != nil || resp.StatusCode != 303 {
		t.Fatalf("retry queued: %v %d", err, resp.StatusCode)
	}
	e, _ := s.GetEmail(id)
	if e.To != "u@right.test" || e.OriginalTo != "u@wrong.test" || e.Attempts != 0 || e.LastError != "" {
		t.Fatalf("after retry of queued email: %+v", e)
	}
}

func TestRetryCanceledEmail(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@dest.test", Subject: "s", BodyText: "b"})
	if err := s.CancelEmail(id); err != nil {
		t.Fatal(err)
	}

	resp, _ := c.PostForm(srv.URL+"/admin/emails/"+strconv.FormatInt(id, 10)+"/retry", url.Values{"to": {"u@dest.test"}})
	if resp.StatusCode != 303 {
		t.Fatalf("retry canceled email should redirect, got %d", resp.StatusCode)
	}
	if e, _ := s.GetEmail(id); e.Status != "queued" {
		t.Fatalf("canceled email should be queued again, got %s", e.Status)
	}
}

// A pasted "Name <addr>" recipient must be split: to_addr stays the bare
// routing address (it drives MX lookup and the SMTP envelope) and the display
// name goes to to_name.
func TestRetrySplitsDisplayNameFromAddress(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@gmial.com", Subject: "s", BodyText: "b"})
	s.MarkFailed(id, "550")

	resp, _ := c.PostForm(srv.URL+"/admin/emails/"+strconv.FormatInt(id, 10)+"/retry",
		url.Values{"to": {"Jens Derond <u@gmail.com>"}})
	if resp.StatusCode != 303 {
		t.Fatalf("retry: %d", resp.StatusCode)
	}
	e, _ := s.GetEmail(id)
	if e.To != "u@gmail.com" || e.ToName != "Jens Derond" {
		t.Fatalf("recipient not split: to_addr=%q to_name=%q", e.To, e.ToName)
	}

	// The detail page pre-fills the input with the full form so an unchanged
	// resubmit doesn't drop the display name.
	resp, _ = c.Get(srv.URL + "/admin/emails/" + strconv.FormatInt(id, 10))
	if body := readBody(t, resp); !strings.Contains(body, "&#34;Jens Derond&#34; &lt;u@gmail.com&gt;") {
		t.Errorf("recipient input should be pre-filled with the display form:\n%s", body)
	}
}

func TestCanceledStatusFilter(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "gone@dest.test", Subject: "s", BodyText: "b"})
	s.CancelEmail(id)
	_, _ = s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "live@dest.test", Subject: "s", BodyText: "b"})

	resp, _ := c.Get(srv.URL + "/admin/emails?status=canceled")
	body := readBody(t, resp)
	if !strings.Contains(body, "gone@dest.test") || strings.Contains(body, "live@dest.test") {
		t.Errorf("canceled filter not applied:\n%s", body)
	}
}

func TestRetryStatusGuard(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@example.com", Subject: "s", BodyText: "b"})
	s.MarkSent(id, "2024-01-01T00:00:00Z")

	resp, _ := c.PostForm(srv.URL+"/admin/emails/"+strconv.FormatInt(id, 10)+"/retry", url.Values{})
	if resp.StatusCode != 409 {
		t.Fatalf("retry on sent email should return 409, got %d", resp.StatusCode)
	}
	e, _ := s.GetEmail(id)
	if e.Status != "sent" {
		t.Fatalf("email should still be sent after failed retry attempt")
	}
}
