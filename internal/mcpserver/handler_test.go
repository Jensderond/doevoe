package mcpserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBearerAuth(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // sentinel: request got through
	})
	h := bearerAuth("sekrit", inner)

	cases := []struct {
		name, header string
		want         int
	}{
		{"no header", "", 401},
		{"wrong scheme", "Basic sekrit", 401},
		{"wrong token", "Bearer nope", 401},
		{"correct", "Bearer sekrit", http.StatusTeapot},
	}
	for _, c := range cases {
		req := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
		if c.header != "" {
			req.Header.Set("Authorization", c.header)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: got %d want %d", c.name, rec.Code, c.want)
		}
	}
}

func TestBearerAuthEmptyConfiguredTokenRejectsAll(t *testing.T) {
	// Defense in depth: main only mounts the handler when a token is set,
	// but an empty token must never mean "allow everything".
	h := bearerAuth("", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer ")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("got %d want 401", rec.Code)
	}
}

func TestHandlerRejectsUnauthenticated(t *testing.T) {
	srv, _, _ := setup(t)
	ts := httptest.NewServer(Handler(srv, "sekrit"))
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated: got %d want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest("POST", ts.URL, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer sekrit")
	req.Header.Set("Content-Type", "application/json")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// The SDK decides what a bare "{}" POST means per negotiated protocol
	// revision; all that matters here is that auth passed.
	if resp.StatusCode == 401 {
		t.Fatal("authenticated request was rejected by bearerAuth")
	}
}
