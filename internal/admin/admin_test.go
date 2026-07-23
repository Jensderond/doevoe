package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"doevoe/internal/dnscheck"
	"doevoe/internal/store"
)

var fakeCheckResult dnscheck.Result

func setFakeCheck(t *testing.T, result dnscheck.Result) {
	fakeCheckResult = result
	t.Cleanup(func() {
		fakeCheckResult = dnscheck.Result{}
	})
}

func adminFixture(t *testing.T) (*store.Store, *httptest.Server, *http.Client) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	a := New(s, "hunter2", "203.0.113.7", "ops@example.com", "mail.example.com")
	a.loginFailDelay = 0 // keep bad-password tests fast
	a.CheckDomain = func(ctx context.Context, d *store.Domain) dnscheck.Result {
		return fakeCheckResult
	}
	mux := http.NewServeMux()
	a.Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	jar := newTestJar(t)
	return s, srv, &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func newTestJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}

func login(t *testing.T, srv *httptest.Server, c *http.Client, password string) *http.Response {
	t.Helper()
	resp, err := c.PostForm(srv.URL+"/admin/login", url.Values{"password": {password}})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestLoginFlow(t *testing.T) {
	_, srv, c := adminFixture(t)

	resp, _ := c.Get(srv.URL + "/admin/emails")
	if resp.StatusCode != 303 {
		t.Fatalf("unauthenticated must redirect, got %d", resp.StatusCode)
	}
	if resp := login(t, srv, c, "wrong"); resp.StatusCode != 401 {
		t.Fatalf("bad password: %d", resp.StatusCode)
	}
	if resp := login(t, srv, c, "hunter2"); resp.StatusCode != 303 {
		t.Fatalf("good password: %d", resp.StatusCode)
	}
	resp, _ = c.Get(srv.URL + "/admin/emails")
	if resp.StatusCode != 200 {
		t.Fatalf("authed emails page: %d", resp.StatusCode)
	}
}

func TestLoginBadPasswordContentType(t *testing.T) {
	_, srv, c := adminFixture(t)

	resp := login(t, srv, c, "wrong")
	if resp.StatusCode != 401 {
		t.Fatalf("bad password should return 401, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Fatalf("401 response must have correct Content-Type, got %q", ct)
	}
}

func TestLayoutIsMobileFirst(t *testing.T) {
	_, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	resp, _ := c.Get(srv.URL + "/admin/emails")
	body := readBody(t, resp)
	if !strings.Contains(body, `name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"`) {
		t.Error("missing viewport meta")
	}
	css, _ := c.Get(srv.URL + "/admin/static/doevoe.css")
	if !strings.Contains(readBody(t, css), "@media (min-width: 48rem)") {
		t.Error("css must be mobile-first (base styles + min-width enhancement)")
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return string(data)
}

func TestVerifyDomainNilCheckDomain(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")

	// Create a domain first
	d, err := s.CreateDomain("example.com", "mail1", "test-private-key")
	if err != nil {
		t.Fatal(err)
	}

	// Create a new request handler with CheckDomain set to nil
	a := New(s, "hunter2", "203.0.113.7", "ops@example.com", "mail.example.com")
	// a.CheckDomain is intentionally nil
	mux := http.NewServeMux()
	a.Routes(mux)
	nilCheckSrv := httptest.NewServer(mux)
	t.Cleanup(nilCheckSrv.Close)

	// Manually create an authenticated request
	jar := newTestJar(t)
	u, _ := url.Parse(nilCheckSrv.URL)
	jar.SetCookies(u, []*http.Cookie{
		{Name: "doevoe_session", Value: "test-session-token", Path: "/admin"},
	})
	// Manually add the session to the admin's session map
	a.mu.Lock()
	a.sessions["test-session-token"] = time.Now().Add(7 * 24 * time.Hour)
	a.mu.Unlock()

	authedClient := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// POST /admin/domains/{id}/verify with nil CheckDomain should return 500
	resp, err := authedClient.PostForm(nilCheckSrv.URL+"/admin/domains/"+fmt.Sprintf("%d", d.ID)+"/verify", url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp.StatusCode)
	}

	// Verify the domain's verification flags remain false
	updated, err := s.GetDomain(d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.SPFVerified || updated.DKIMVerified || updated.DMARCVerified {
		t.Fatalf("expected all verification flags to be false, got SPF=%v DKIM=%v DMARC=%v",
			updated.SPFVerified, updated.DKIMVerified, updated.DMARCVerified)
	}
}

func TestServesHtmx(t *testing.T) {
	_, srv, c := adminFixture(t)
	resp, err := c.Get(srv.URL + "/admin/static/htmx.min.js")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if body := readBody(t, resp); len(body) < 1000 {
		t.Errorf("htmx.min.js too small: %d bytes", len(body))
	}
}

func TestHXRequestReturnsFragment(t *testing.T) {
	_, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	req, _ := http.NewRequest("GET", srv.URL+"/admin/emails", nil)
	req.Header.Set("HX-Request", "true")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if strings.Contains(body, "<!doctype html>") || strings.Contains(body, "<html") {
		t.Error("HX fragment must not contain the full document")
	}
	if !strings.Contains(body, `id="shell"`) {
		t.Error("fragment must contain the shell element")
	}
}

func TestFullPageWithoutHXRequest(t *testing.T) {
	_, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	resp, err := c.Get(srv.URL + "/admin/emails")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(readBody(t, resp), "<!doctype html>") {
		t.Error("normal request must return the full document")
	}
}

func TestExpiredSessionHXRedirect(t *testing.T) {
	_, srv, c := adminFixture(t) // never logs in → unauthenticated
	req, _ := http.NewRequest("GET", srv.URL+"/admin/emails", nil)
	req.Header.Set("HX-Request", "true")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("HX-Redirect"); got != "/admin/login" {
		t.Errorf("HX-Redirect = %q, want /admin/login", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestDashboardShowsKPIs(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, err := s.CreateDomain("a.test", "mail1", "pk")
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@a.test", To: "b@b.test", Subject: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSent(id, store.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(srv.URL + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "Success rate") {
		t.Error("dashboard should show the success-rate KPI")
	}
	if !strings.Contains(body, "Overview") {
		t.Error("dashboard should show the Overview heading/nav")
	}
}

func TestDashboardEmbedsChartData(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, err := s.CreateDomain("a.test", "mail1", "pk")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		id, err := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@a.test", To: "b@b.test", Subject: "hi"})
		if err != nil {
			t.Fatal(err)
		}
		if err := s.MarkSent(id, store.Now()); err != nil {
			t.Fatal(err)
		}
	}
	id, err := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@a.test", To: "c@c.test", Subject: "bye"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkFailed(id, "550 mailbox unavailable"); err != nil {
		t.Fatal(err)
	}

	resp, err := c.Get(srv.URL + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, `id="dashboard-data"`) {
		t.Fatal("dashboard should embed chart data in a #dashboard-data script tag")
	}
	m := regexp.MustCompile(`(?s)<script id="dashboard-data" type="application/json">(.*?)</script>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("could not locate the dashboard-data JSON script tag")
	}
	var data struct {
		RangeDays int `json:"rangeDays"`
		Daily     []struct {
			Date   string `json:"date"`
			Sent   int    `json:"sent"`
			Failed int    `json:"failed"`
		} `json:"daily"`
		Domains []struct {
			Name   string `json:"name"`
			Sent   int    `json:"sent"`
			Failed int    `json:"failed"`
		} `json:"domains"`
		Reasons []struct {
			Reason string `json:"reason"`
			Count  int    `json:"count"`
		} `json:"reasons"`
	}
	if err := json.Unmarshal([]byte(m[1]), &data); err != nil {
		t.Fatalf("embedded dashboard data must be valid JSON: %v", err)
	}
	if data.RangeDays != 30 {
		t.Errorf("rangeDays = %d, want 30", data.RangeDays)
	}
	if len(data.Daily) != 30 {
		t.Fatalf("daily must be gap-filled to 30 entries, got %d", len(data.Daily))
	}
	today := time.Now().UTC().Format("2006-01-02")
	last := data.Daily[len(data.Daily)-1]
	if last.Date != today {
		t.Errorf("last daily entry = %q, want today %q (oldest→newest)", last.Date, today)
	}
	if last.Sent != 2 || last.Failed != 1 {
		t.Errorf("today's counts = %d sent / %d failed, want 2/1", last.Sent, last.Failed)
	}
	if len(data.Domains) != 1 || data.Domains[0].Name != "a.test" ||
		data.Domains[0].Sent != 2 || data.Domains[0].Failed != 1 {
		t.Errorf("domains = %+v, want [a.test 2 sent / 1 failed]", data.Domains)
	}
	if len(data.Reasons) != 1 || data.Reasons[0].Reason != "550 mailbox unavailable" || data.Reasons[0].Count != 1 {
		t.Errorf("reasons = %+v, want [550 mailbox unavailable ×1]", data.Reasons)
	}
}

func TestDashboardRangeToggle(t *testing.T) {
	_, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	resp, err := c.Get(srv.URL + "/admin/?range=7")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(readBody(t, resp), `href="/admin/?range=7" class="active"`) {
		t.Error("range=7 should mark the 7d toggle active")
	}
}
