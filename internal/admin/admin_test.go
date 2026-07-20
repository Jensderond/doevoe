package admin

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"doevoe/internal/store"
)

func adminFixture(t *testing.T) (*store.Store, *httptest.Server, *http.Client) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	a := New(s, "hunter2", "203.0.113.7", "ops@example.com", "mail.example.com")
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
