package api

import (
	"encoding/json"
	"fmt"
	"io"
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

func (f *fixture) get(t *testing.T, id int64, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/emails/%d", f.srv.URL, id), nil)
	req.Header.Set("Authorization", "Bearer "+token)
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
	resp := f.post(t, validBody, f.token, "")
	if resp.StatusCode != 403 {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "DNS") {
		t.Fatalf("want body to mention DNS, got %s", body)
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

// TestCrossDomainGetIsolation covers Finding 1: two verified domains, each
// with its own API key. An email created under domain A's key must not be
// readable with domain B's key, even though both keys are valid and both
// domains are verified - GetEmail must 404 rather than leak another
// tenant's data.
func TestCrossDomainGetIsolation(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	dA, _ := s.CreateDomain("a.example.com", "mail1", "PEM")
	s.SetDomainVerification(dA.ID, true, true, true, store.Now())
	dA, _ = s.GetDomain(dA.ID)
	dB, _ := s.CreateDomain("b.example.com", "mail1", "PEM")
	s.SetDomainVerification(dB.ID, true, true, true, store.Now())
	dB, _ = s.GetDomain(dB.ID)

	tokenA, hashA, err := store.GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	s.CreateAPIKey("keyA", dA.ID, hashA)
	tokenB, hashB, err := store.GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	s.CreateAPIKey("keyB", dB.ID, hashB)

	mux := http.NewServeMux()
	(&Server{Store: s}).Routes(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	f := &fixture{store: s, srv: srv}

	body := `{"from":"info@a.example.com","to":"u@dest.test","subject":"Hi","text":"yo"}`
	resp := f.post(t, body, tokenA, "")
	if resp.StatusCode != 202 {
		t.Fatalf("create status %d", resp.StatusCode)
	}
	var created struct {
		ID int64 `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&created)
	if created.ID == 0 {
		t.Fatalf("no id created: %+v", created)
	}

	if got := f.get(t, created.ID, tokenB); got.StatusCode != 404 {
		t.Fatalf("cross-domain GET with key B: want 404, got %d", got.StatusCode)
	}
	if got := f.get(t, created.ID, tokenA); got.StatusCode != 200 {
		t.Fatalf("same-domain GET with key A: want 200, got %d", got.StatusCode)
	}
}

// TestIdempotencyIndexRejectsDuplicate covers the storage-layer half of
// Finding 2: it proves the partial unique index (api_key_id,
// idempotency_key) actually fires on a second insert with the same pair.
// This is what makes the handler's check-then-insert racy in the first
// place - two concurrent requests can both pass FindByIdempotencyKey (miss)
// and then race to EnqueueEmail, and only one of those inserts can win.
func TestIdempotencyIndexRejectsDuplicate(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	kid, _ := s.CreateAPIKey("k", d.ID, "h")

	e := &store.Email{APIKeyID: kid, DomainID: d.ID, From: "a@example.com", To: "b@dest.test",
		Subject: "s", BodyText: "t", IdempotencyKey: "race-key"}
	if _, err := s.EnqueueEmail(e); err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if _, err := s.EnqueueEmail(e); err == nil {
		t.Fatal("want error inserting a second row with the same (api_key_id, idempotency_key)")
	}
}

// TestEnqueueOrReplayRecoversFromIndexRace covers the handler-recovery half
// of Finding 2. Deterministically driving the actual concurrent race
// through the HTTP handler isn't reproducible without flakiness (the whole
// point is that both requests pass the pre-check before either inserts), so
// this instead unit-tests the extracted enqueueOrReplay helper directly:
// it pre-creates a row with idempotency key K (standing in for the
// racing request that won), then calls enqueueOrReplay with a second,
// distinct Email that reuses the same (api_key_id, idempotency_key) pair
// (standing in for the request that lost the race and whose EnqueueEmail
// call fails against idx_emails_idem). The helper must recover by finding
// the winning row and returning it as a replay, not surface the raw insert
// error as a 500.
func TestEnqueueOrReplayRecoversFromIndexRace(t *testing.T) {
	f := setup(t, true)
	k, err := f.store.GetAPIKeyByHash(store.HashAPIKey(f.token))
	if err != nil || k == nil {
		t.Fatalf("lookup api key: %v", err)
	}

	winner := &store.Email{APIKeyID: k.ID, DomainID: f.domain.ID, From: "info@example.com", To: "u@dest.test",
		Subject: "s", BodyText: "t", IdempotencyKey: "race-key"}
	winnerID, err := f.store.EnqueueEmail(winner)
	if err != nil {
		t.Fatalf("seed winning insert: %v", err)
	}

	loser := &store.Email{APIKeyID: k.ID, DomainID: f.domain.ID, From: "info@example.com", To: "other@dest.test",
		Subject: "s2", BodyText: "t2", IdempotencyKey: "race-key"}
	id, status, replay, err := enqueueOrReplay(f.store, loser)
	if err != nil {
		t.Fatalf("enqueueOrReplay: %v", err)
	}
	if !replay {
		t.Fatal("want replay=true when the insert loses the index race")
	}
	if id != winnerID {
		t.Fatalf("id = %d, want winning row's id %d", id, winnerID)
	}
	if status != "queued" {
		t.Fatalf("status = %q, want queued", status)
	}
}

// TestPostIngressValidation covers Finding 3: reply_to and custom headers
// must be validated at ingress (422) rather than only at send time, where a
// rejected email would already be stuck in the queue unable to ever send.
func TestPostIngressValidation(t *testing.T) {
	f := setup(t, true)

	// Tagged to match the wire spec (snake_case reply_to) rather than relying
	// on Go's default field-name marshaling, since sendRequest now requires
	// an exact (or case-insensitive, non-underscore) tag match to decode.
	type body struct {
		From    string            `json:"from"`
		To      string            `json:"to"`
		Subject string            `json:"subject"`
		Text    string            `json:"text"`
		ReplyTo string            `json:"reply_to"`
		Headers map[string]string `json:"headers,omitempty"`
	}
	marshal := func(b body) string {
		out, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}

	cases := []struct {
		name string
		b    body
	}{
		{
			name: "CRLF in subject",
			b:    body{From: "info@example.com", To: "u@dest.test", Subject: "Hi\r\nBcc: evil@example.com", Text: "yo"},
		},
		{
			name: "CRLF in custom header value",
			b: body{From: "info@example.com", To: "u@dest.test", Subject: "Hi", Text: "yo",
				Headers: map[string]string{"X-Custom": "val\r\nBcc: evil@example.com"}},
		},
		{
			name: "reserved custom header name",
			b: body{From: "info@example.com", To: "u@dest.test", Subject: "Hi", Text: "yo",
				Headers: map[string]string{"Bcc": "evil@example.com"}},
		},
		{
			name: "unparseable reply_to",
			b:    body{From: "info@example.com", To: "u@dest.test", Subject: "Hi", Text: "yo", ReplyTo: "not an address"},
		},
	}
	for _, c := range cases {
		if resp := f.post(t, marshal(c.b), f.token, ""); resp.StatusCode != 422 {
			t.Errorf("%s: got %d want 422", c.name, resp.StatusCode)
		}
	}
}

// TestPostEmailReplyToJSONTag is a regression test for the critical finding
// that sendRequest had no JSON tags: encoding/json's case-insensitive
// fallback does not bridge "reply_to" (wire format) to "ReplyTo" (Go field
// name) because it ignores case but not underscores, so reply_to silently
// decoded to "". This POSTs a raw, hand-written JSON string shaped exactly
// like the public API spec (not marshaled from any Go struct, so there is
// no way for the test itself to accidentally paper over the bug) and
// asserts the stored row actually captured ReplyTo.
func TestPostEmailReplyToJSONTag(t *testing.T) {
	f := setup(t, true)
	const body = `{"from":"info@example.com","to":"u@dest.test","subject":"Hi","text":"yo","reply_to":"support@example.com"}`
	resp := f.post(t, body, f.token, "")
	if resp.StatusCode != 202 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var out struct {
		ID int64 `json:"id"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	e, err := f.store.GetEmail(out.ID)
	if err != nil {
		t.Fatal(err)
	}
	if e.ReplyTo != "support@example.com" {
		t.Fatalf("ReplyTo = %q, want %q", e.ReplyTo, "support@example.com")
	}
}

// TestPostEmailOversizedBodyRejected covers Finding 5: a request body over
// maxRequestBodyBytes must be rejected with 413 rather than decoded (and
// potentially exhausting memory) in full.
func TestPostEmailOversizedBodyRejected(t *testing.T) {
	f := setup(t, true)
	huge := strings.Repeat("a", 11<<20) // 11MB, over the 10MB cap
	body := `{"from":"info@example.com","to":"u@dest.test","subject":"Hi","text":"` + huge + `"}`
	resp := f.post(t, body, f.token, "")
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d, want 413", resp.StatusCode)
	}
}
