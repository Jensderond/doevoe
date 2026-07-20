package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"doevoe/internal/store"
)

type fixture struct {
	store  *store.Store
	srv    *httptest.Server
	token  string
	domain *store.Domain
}

func setup(t *testing.T, verified bool) *fixture {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	if verified {
		s.SetDomainVerification(d.ID, true, true, true, store.Now())
		d, _ = s.GetDomain(d.ID)
	}
	token, hash, err := store.GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	s.CreateAPIKey("test", d.ID, hash)
	mux := http.NewServeMux()
	(&Server{Store: s}).Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &fixture{store: s, srv: srv, token: token, domain: d}
}

func (f *fixture) post(t *testing.T, body, token, idemKey string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", f.srv.URL+"/api/v1/emails", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	if idemKey != "" {
		req.Header.Set("Idempotency-Key", idemKey)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

const validBody = `{"from":"info@example.com","to":"u@dest.test","subject":"Hi","text":"yo"}`

func TestPostEmailQueues(t *testing.T) {
	f := setup(t, true)
	resp := f.post(t, validBody, f.token, "")
	if resp.StatusCode != 202 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out struct {
		ID     int64  `json:"id"`
		Status string `json:"status"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	if out.Status != "queued" || out.ID == 0 {
		t.Fatalf("%+v", out)
	}
	e, _ := f.store.GetEmail(out.ID)
	if e.To != "u@dest.test" || e.DomainID != f.domain.ID {
		t.Fatalf("row: %+v", e)
	}
}

func TestPostRejections(t *testing.T) {
	f := setup(t, true)
	cases := []struct {
		name, body, token string
		want              int
	}{
		{"bad token", validBody, "dv_wrong", 401},
		{"foreign from domain", `{"from":"a@other.com","to":"u@dest.test","subject":"s","text":"t"}`, f.token, 422},
		{"invalid to", `{"from":"info@example.com","to":"not-an-address","subject":"s","text":"t"}`, f.token, 422},
		{"no body", `{"from":"info@example.com","to":"u@dest.test","subject":"s"}`, f.token, 422},
	}
	for _, c := range cases {
		if resp := f.post(t, c.body, c.token, ""); resp.StatusCode != c.want {
			t.Errorf("%s: got %d want %d", c.name, resp.StatusCode, c.want)
		}
	}
}

func TestPostUnverifiedDomainFailsClosed(t *testing.T) {
	f := setup(t, false)
	if resp := f.post(t, validBody, f.token, ""); resp.StatusCode != 403 {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

func TestIdempotencyReplay(t *testing.T) {
	f := setup(t, true)
	r1 := f.post(t, validBody, f.token, "same-key")
	r2 := f.post(t, validBody, f.token, "same-key")
	var a, b struct {
		ID int64 `json:"id"`
	}
	json.NewDecoder(r1.Body).Decode(&a)
	json.NewDecoder(r2.Body).Decode(&b)
	if r1.StatusCode != 202 || r2.StatusCode != 200 || a.ID != b.ID {
		t.Fatalf("idempotency: %d/%d ids %d/%d", r1.StatusCode, r2.StatusCode, a.ID, b.ID)
	}
}

func TestGetEmailStatus(t *testing.T) {
	f := setup(t, true)
	resp := f.post(t, validBody, f.token, "")
	var created struct {
		ID int64 `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&created)

	req, _ := http.NewRequest("GET", f.srv.URL+"/api/v1/emails/1", nil)
	req.Header.Set("Authorization", "Bearer "+f.token)
	got, _ := http.DefaultClient.Do(req)
	if got.StatusCode != 200 {
		t.Fatalf("status %d", got.StatusCode)
	}
	var out struct {
		Status string `json:"status"`
	}
	json.NewDecoder(got.Body).Decode(&out)
	if out.Status != "queued" {
		t.Fatalf("%+v", out)
	}
}
