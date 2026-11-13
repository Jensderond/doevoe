package delivery

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"doevoe/internal/store"
)

type relayCall struct {
	auth, idem string
	body       map[string]any
}

// relayFixture serves answer(status, body) for every request and records
// what it was sent.
func relayFixture(t *testing.T, status int, answer string) (*EmailEU, *[]relayCall) {
	t.Helper()
	var calls []relayCall
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		c := relayCall{auth: r.Header.Get("Authorization"), idem: r.Header.Get("Idempotency-Key")}
		if err := json.Unmarshal(raw, &c.body); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		calls = append(calls, c)
		w.WriteHeader(status)
		io.WriteString(w, answer)
	}))
	t.Cleanup(srv.Close)
	p := NewEmailEU()
	p.Endpoint = srv.URL + "/api/v1/send"
	return p, &calls
}

var relayDomain = &store.Domain{Name: "example.com", Provider: store.ProviderEmailEU, ProviderAPIKey: "eu_secret"}

func relayEmail() *store.Email {
	return &store.Email{
		ID: 42, From: "noreply@example.com", FromName: "Shop Zoë", To: "anna@dest.test", ToName: "Anna",
		ReplyTo: "Help <help@example.com>", Subject: "Your order", BodyText: "Thanks!", BodyHTML: "<p>Thanks!</p>",
		HeadersJSON: `{"X-Order":"1001"}`, AttachmentCount: 2,
		Attachments: []store.Attachment{
			{Filename: "invoice.pdf", ContentType: "application/pdf", Disposition: DispositionAttachment, ContentID: "ignored", Content: []byte("PDF")},
			{Filename: "logo.png", ContentType: "image/png", Disposition: DispositionInline, ContentID: "logo", Content: []byte("PNG")},
		},
	}
}

func TestEmailEUSendMapsTheEmail(t *testing.T) {
	p, calls := relayFixture(t, 202, `{"id":"7f3c","status":"queued"}`)
	res := p.Send(context.Background(), relayEmail(), relayDomain)
	if res.Err != nil || res.Code != 202 || !strings.Contains(res.Response, "7f3c") {
		t.Fatalf("result: %+v", res)
	}
	if len(*calls) != 1 {
		t.Fatalf("calls: %d", len(*calls))
	}
	c := (*calls)[0]
	if c.auth != "Bearer eu_secret" {
		t.Errorf("Authorization = %q", c.auth)
	}
	want := map[string]any{
		"from":     map[string]any{"email": "noreply@example.com", "name": "Shop Zoë"},
		"to":       map[string]any{"email": "anna@dest.test", "name": "Anna"},
		"reply_to": map[string]any{"email": "help@example.com", "name": "Help"},
		"subject":  "Your order", "text": "Thanks!", "html": "<p>Thanks!</p>",
		"headers": map[string]any{"X-Order": "1001"},
		"attachments": []any{
			// A plain attachment must not carry a content_id, or the
			// provider would treat it as an inline part.
			map[string]any{"filename": "invoice.pdf", "content": "UERG", "content_type": "application/pdf"},
			map[string]any{"filename": "logo.png", "content": "UE5H", "content_type": "image/png", "content_id": "logo"},
		},
	}
	got, _ := json.Marshal(c.body)
	wantJSON, _ := json.Marshal(want)
	if string(got) != string(wantJSON) {
		t.Errorf("body:\n got %s\nwant %s", got, wantJSON)
	}
}

// The Idempotency-Key is what keeps a retry after a lost response from
// sending twice, so it must be identical across attempts of the same email
// and different once the request itself differs.
func TestEmailEUIdempotencyKey(t *testing.T) {
	p, calls := relayFixture(t, 202, `{"id":"x","repeated":true}`)
	e := relayEmail()
	p.Send(context.Background(), e, relayDomain)
	res := p.Send(context.Background(), e, relayDomain)
	if !strings.Contains(res.Response, "already accepted") {
		t.Errorf("repeated answer not reflected: %q", res.Response)
	}
	e.To = "other@dest.test" // admin retry to a corrected address
	p.Send(context.Background(), e, relayDomain)
	other := relayEmail()
	other.ID = 43
	p.Send(context.Background(), other, relayDomain)

	k := *calls
	if !strings.HasPrefix(k[0].idem, "doevoe-42-") || k[0].idem != k[1].idem {
		t.Errorf("same email, same request: keys %q and %q", k[0].idem, k[1].idem)
	}
	if k[2].idem == k[0].idem || k[3].idem == k[0].idem {
		t.Errorf("a changed request or another email reused the key: %q %q %q", k[0].idem, k[2].idem, k[3].idem)
	}
}

func TestEmailEUErrorClassification(t *testing.T) {
	cases := []struct {
		status int
		body   string
		want   Class
	}{
		{422, `{"error":{"code":"invalid","message":"subject is required"}}`, ClassPerm},
		{400, `not json`, ClassPerm},
		// Configuration problems: the queue holds the mail until it's fixed.
		{401, `{"error":{"code":"unauthorized","message":"unknown key"}}`, ClassTemp},
		{403, `{"error":{"code":"forbidden_sender","message":"not on one of the key's domains"}}`, ClassTemp},
		{429, `{"error":{"code":"too_fast","message":"slow down"}}`, ClassTemp},
		{500, ``, ClassTemp},
		{302, ``, ClassTemp},
	}
	for _, c := range cases {
		p, _ := relayFixture(t, c.status, c.body)
		res := p.Send(context.Background(), relayEmail(), relayDomain)
		if res.Err == nil || res.Code != c.status {
			t.Errorf("%d: result %+v", c.status, res)
			continue
		}
		if got := Classify(res.Err); got != c.want {
			t.Errorf("%d: Classify = %v, want %v", c.status, got, c.want)
		}
	}
	p, _ := relayFixture(t, 403, `{"error":{"code":"forbidden_sender","message":"not on one of the key's domains"}}`)
	if res := p.Send(context.Background(), relayEmail(), relayDomain); !strings.Contains(res.Response, "forbidden_sender") {
		t.Errorf("provider's error code missing from the attempt log: %q", res.Response)
	}
}

func TestEmailEUNetworkErrorIsTemporary(t *testing.T) {
	p, _ := relayFixture(t, 202, `{}`)
	p.Endpoint = "http://127.0.0.1:1/api/v1/send"
	res := p.Send(context.Background(), relayEmail(), relayDomain)
	if res.Err == nil || Classify(res.Err) != ClassTemp {
		t.Fatalf("result: %+v", res)
	}
}

func TestEmailEURefusesUnloadedAttachments(t *testing.T) {
	p, calls := relayFixture(t, 202, `{}`)
	e := relayEmail()
	e.Attachments = nil
	res := p.Send(context.Background(), e, relayDomain)
	if res.Err == nil || len(*calls) != 0 || Classify(res.Err) != ClassTemp {
		t.Fatalf("must fail before any request: %+v, calls %d", res, len(*calls))
	}
}

func TestRoutePicksByDomainProvider(t *testing.T) {
	var got string
	mk := func(name string) SendFunc {
		return func(context.Context, *store.Email, *store.Domain) Result { got = name; return Result{} }
	}
	send := Route(mk("direct"), mk("relay"))
	send(context.Background(), &store.Email{}, &store.Domain{Provider: store.ProviderDirect})
	if got != "direct" {
		t.Errorf("direct domain went to %s", got)
	}
	send(context.Background(), &store.Email{}, relayDomain)
	if got != "relay" {
		t.Errorf("relayed domain went to %s", got)
	}
}
