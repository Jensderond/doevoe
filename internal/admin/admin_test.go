package admin

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
	if !strings.Contains(body, `name="viewport" content="width=device-width, initial-scale=1"`) {
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
