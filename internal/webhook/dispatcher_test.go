package webhook

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"doevoe/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// capture records the requests a fake receiver saw.
type capture struct {
	mu      sync.Mutex
	headers []http.Header
	bodies  []string
}

func (c *capture) add(r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	buf := make([]byte, r.ContentLength)
	r.Body.Read(buf)
	c.headers = append(c.headers, r.Header.Clone())
	c.bodies = append(c.bodies, string(buf))
}

func (c *capture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.bodies)
}

func receiver(t *testing.T, status int, body string) (*httptest.Server, *capture) {
	t.Helper()
	cap := &capture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.add(r)
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, cap
}

func sentEmail(t *testing.T, s *store.Store) (*store.Domain, int64) {
	t.Helper()
	d, err := s.CreateDomain("a.test", "mail1", "PEM")
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.EnqueueEmail(&store.Email{
		DomainID: d.ID, From: "from@a.test", To: "to@b.test", Subject: "hi", BodyText: "yo",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSent(id, store.Now()); err != nil {
		t.Fatal(err)
	}
	return d, id
}

func TestEmailEventFansOutToSubscribersOnly(t *testing.T) {
	s := testStore(t)
	_, emailID := sentEmail(t, s)
	subscribed, _ := s.CreateWebhook("subscribed", "https://recv.test/h", "sec", []string{EventEmailSent})
	otherEvent, _ := s.CreateWebhook("other", "https://recv.test/h", "sec", []string{EventEmailFailed})
	paused, _ := s.CreateWebhook("paused", "https://recv.test/h", "sec", []string{EventEmailSent})
	if err := s.UpdateWebhook(paused.ID, paused.Name, paused.URL, paused.Events, false); err != nil {
		t.Fatal(err)
	}

	d := &Dispatcher{Store: s}
	d.EmailEvent(EventEmailSent, emailID)

	for _, tc := range []struct {
		hook *store.Webhook
		want int
	}{{subscribed, 1}, {otherEvent, 0}, {paused, 0}} {
		got, err := s.ListWebhookDeliveries(tc.hook.ID, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != tc.want {
			t.Errorf("%s: queued %d deliveries, want %d", tc.hook.Name, len(got), tc.want)
		}
	}
}

func TestEmailEventPayloadSnapshot(t *testing.T) {
	s := testStore(t)
	_, emailID := sentEmail(t, s)
	hook, _ := s.CreateWebhook("h", "https://recv.test/h", "sec", []string{EventEmailSent})

	(&Dispatcher{Store: s}).EmailEvent(EventEmailSent, emailID)

	deliveries, _ := s.ListWebhookDeliveries(hook.ID, 10)
	if len(deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(deliveries))
	}
	var got struct {
		Event     string `json:"event"`
		CreatedAt string `json:"created_at"`
		Data      struct {
			Email struct {
				ID      int64  `json:"id"`
				Status  string `json:"status"`
				Domain  string `json:"domain"`
				From    string `json:"from"`
				To      string `json:"to"`
				Subject string `json:"subject"`
				SentAt  string `json:"sent_at"`
			} `json:"email"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(deliveries[0].Payload), &got); err != nil {
		t.Fatalf("payload must be valid JSON: %v (%s)", err, deliveries[0].Payload)
	}
	if got.Event != EventEmailSent || got.CreatedAt == "" {
		t.Errorf("envelope = %+v", got)
	}
	e := got.Data.Email
	if e.ID != emailID || e.Status != "sent" || e.Domain != "a.test" ||
		e.From != "from@a.test" || e.To != "to@b.test" || e.Subject != "hi" || e.SentAt == "" {
		t.Errorf("email data = %+v", e)
	}
	if deliveries[0].EmailID != emailID {
		t.Errorf("delivery email_id = %d, want %d", deliveries[0].EmailID, emailID)
	}
}

func TestDomainEventPayload(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("a.test", "mail1", "PEM")
	if err := s.SetDomainVerification(d.ID, true, true, true, store.Now()); err != nil {
		t.Fatal(err)
	}
	hook, _ := s.CreateWebhook("h", "https://recv.test/h", "sec", []string{EventDomainVerified})

	(&Dispatcher{Store: s}).DomainEvent(EventDomainVerified, d.ID)

	deliveries, _ := s.ListWebhookDeliveries(hook.ID, 10)
	if len(deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(deliveries))
	}
	var got struct {
		Event string `json:"event"`
		Data  struct {
			Domain struct {
				Name     string `json:"name"`
				Verified bool   `json:"verified"`
				SPF      bool   `json:"spf_verified"`
			} `json:"domain"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(deliveries[0].Payload), &got); err != nil {
		t.Fatal(err)
	}
	if got.Event != EventDomainVerified || got.Data.Domain.Name != "a.test" ||
		!got.Data.Domain.Verified || !got.Data.Domain.SPF {
		t.Errorf("domain payload = %+v", got)
	}
	if deliveries[0].EmailID != 0 {
		t.Errorf("email_id = %d, want 0 for a domain event", deliveries[0].EmailID)
	}
}

// An emit with nothing subscribed must not touch the deliveries table at all.
func TestEmitWithoutSubscribersIsNoop(t *testing.T) {
	s := testStore(t)
	_, emailID := sentEmail(t, s)
	hook, _ := s.CreateWebhook("h", "https://recv.test/h", "sec", []string{EventEmailFailed})

	(&Dispatcher{Store: s}).EmailEvent(EventEmailSent, emailID)

	if got, _ := s.ListWebhookDeliveries(hook.ID, 10); len(got) != 0 {
		t.Fatalf("deliveries = %d, want 0", len(got))
	}
}

func TestTickDeliversSignedPayload(t *testing.T) {
	s := testStore(t)
	_, emailID := sentEmail(t, s)
	srv, cap := receiver(t, 200, "ok")
	hook, _ := s.CreateWebhook("h", srv.URL, "whsec_test", []string{EventEmailSent})

	d := &Dispatcher{Store: s, Client: srv.Client()}
	d.EmailEvent(EventEmailSent, emailID)
	if err := d.Tick(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}

	if cap.count() != 1 {
		t.Fatalf("receiver saw %d requests, want 1", cap.count())
	}
	h, body := cap.headers[0], cap.bodies[0]
	if h.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", h.Get("Content-Type"))
	}
	if h.Get("X-Doevoe-Event") != EventEmailSent {
		t.Errorf("X-Doevoe-Event = %q", h.Get("X-Doevoe-Event"))
	}
	if h.Get("X-Doevoe-Attempt") != "1" {
		t.Errorf("X-Doevoe-Attempt = %q, want 1", h.Get("X-Doevoe-Attempt"))
	}
	ts := h.Get("X-Doevoe-Timestamp")
	if ts == "" {
		t.Fatal("missing X-Doevoe-Timestamp")
	}
	if want := Sign("whsec_test", ts, []byte(body)); h.Get("X-Doevoe-Signature") != want {
		t.Errorf("signature = %q, want %q", h.Get("X-Doevoe-Signature"), want)
	}

	deliveries, _ := s.ListWebhookDeliveries(hook.ID, 10)
	if deliveries[0].Status != "delivered" || deliveries[0].ResponseCode != 200 || deliveries[0].Attempts != 1 {
		t.Fatalf("delivery = %+v", deliveries[0])
	}
	updated, _ := s.GetWebhook(hook.ID)
	if updated.LastStatus != 200 || updated.LastError != "" || updated.LastDeliveryAt == "" {
		t.Fatalf("endpoint health = %+v", updated)
	}
}

// The signature must cover the exact bytes sent, so a receiver recomputing it
// over the raw body agrees. Guards against a future change that re-marshals
// the payload per attempt.
func TestSignCoversRawBody(t *testing.T) {
	sig := Sign("secret", "1700000000", []byte(`{"event":"email.sent"}`))
	if sig != Sign("secret", "1700000000", []byte(`{"event":"email.sent"}`)) {
		t.Fatal("Sign must be deterministic")
	}
	if sig == Sign("secret", "1700000001", []byte(`{"event":"email.sent"}`)) {
		t.Error("signature must depend on the timestamp")
	}
	if sig == Sign("other", "1700000000", []byte(`{"event":"email.sent"}`)) {
		t.Error("signature must depend on the secret")
	}
	if len(sig) != len("sha256=")+64 {
		t.Errorf("signature = %q, want sha256=<64 hex chars>", sig)
	}
}

func TestTickRetriesOn5xxThenExhausts(t *testing.T) {
	s := testStore(t)
	_, emailID := sentEmail(t, s)
	srv, cap := receiver(t, 503, "unavailable")
	hook, _ := s.CreateWebhook("h", srv.URL, "sec", []string{EventEmailSent})

	d := &Dispatcher{Store: s, Client: srv.Client()}
	d.EmailEvent(EventEmailSent, emailID)

	now := time.Now()
	if err := d.Tick(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	deliveries, _ := s.ListWebhookDeliveries(hook.ID, 10)
	del := deliveries[0]
	if del.Status != "queued" || del.Attempts != 1 || del.ResponseCode != 503 {
		t.Fatalf("after first failure: %+v", del)
	}
	if del.LastError == "" {
		t.Error("failed delivery must record the response")
	}
	if next := store.ParseTime(del.NextAttemptAt); !next.After(now) {
		t.Errorf("next attempt %v must be in the future", next)
	}

	// Walk the whole schedule: each tick runs at the row's due time.
	for i := 0; i < len(Schedule)+1; i++ {
		del, err := s.GetWebhookDelivery(del.ID)
		if err != nil {
			t.Fatal(err)
		}
		if del.Status == "failed" {
			break
		}
		if err := d.Tick(context.Background(), store.ParseTime(del.NextAttemptAt)); err != nil {
			t.Fatal(err)
		}
	}
	final, _ := s.GetWebhookDelivery(del.ID)
	if final.Status != "failed" {
		t.Fatalf("status = %q after exhausting the schedule, want failed (%+v)", final.Status, final)
	}
	if final.Attempts != len(Schedule)+1 {
		t.Errorf("attempts = %d, want %d", final.Attempts, len(Schedule)+1)
	}
	if cap.count() != len(Schedule)+1 {
		t.Errorf("receiver saw %d requests, want %d", cap.count(), len(Schedule)+1)
	}
}

func TestTickGoneIsPermanent(t *testing.T) {
	s := testStore(t)
	_, emailID := sentEmail(t, s)
	srv, cap := receiver(t, http.StatusGone, "stop")
	hook, _ := s.CreateWebhook("h", srv.URL, "sec", []string{EventEmailSent})

	d := &Dispatcher{Store: s, Client: srv.Client()}
	d.EmailEvent(EventEmailSent, emailID)
	if err := d.Tick(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}

	deliveries, _ := s.ListWebhookDeliveries(hook.ID, 10)
	if deliveries[0].Status != "failed" || deliveries[0].Attempts != 1 {
		t.Fatalf("410 must fail immediately without retries: %+v", deliveries[0])
	}
	if cap.count() != 1 {
		t.Errorf("receiver saw %d requests, want 1", cap.count())
	}
}

// An endpoint deleted while one of its deliveries is in flight must not turn
// into an endless retry loop (or a POST to an empty URL).
func TestDeletedEndpointMidFlight(t *testing.T) {
	s := testStore(t)
	hook, _ := s.CreateWebhook("h", "https://recv.test/h", "sec", []string{EventEmailSent})
	if _, err := s.EnqueueWebhookDelivery(&store.WebhookDelivery{
		WebhookID: hook.ID, Event: EventEmailSent, Payload: "{}",
	}); err != nil {
		t.Fatal(err)
	}
	claimed, err := s.ClaimDueWebhookDeliveries(1, store.Now())
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %+v %v", claimed, err)
	}
	if err := s.DeleteWebhook(hook.ID); err != nil {
		t.Fatal(err)
	}

	// The in-flight row was deleted along with the endpoint; processing it
	// must be a quiet no-op rather than a panic or a network call.
	(&Dispatcher{Store: s, Client: &http.Client{Transport: failTransport{t}}}).
		process(context.Background(), claimed[0], time.Now())

	if left, err := s.ClaimDueWebhookDeliveries(10, store.Now()); err != nil || len(left) != 0 {
		t.Fatalf("deliveries left = %+v %v, want none", left, err)
	}
}

// failTransport fails the test if a delivery attempt reaches the network.
type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("unexpected POST to %s", r.URL)
	return nil, http.ErrUseLastResponse
}

func TestTestEventQueuesDelivery(t *testing.T) {
	s := testStore(t)
	hook, _ := s.CreateWebhook("h", "https://recv.test/h", "sec", []string{EventEmailSent})

	d := &Dispatcher{Store: s}
	if err := d.Test(hook.ID); err != nil {
		t.Fatal(err)
	}
	deliveries, _ := s.ListWebhookDeliveries(hook.ID, 10)
	if len(deliveries) != 1 || deliveries[0].Event != EventTest {
		t.Fatalf("deliveries = %+v, want one %s", deliveries, EventTest)
	}
	if err := d.Test(hook.ID + 999); err == nil {
		t.Error("Test on a missing endpoint must report an error")
	}
}

// doevoe's own notification mail rides the same queue, so it produces the same
// events; consumers need the system flag to tell it apart.
func TestSystemEmailIsFlagged(t *testing.T) {
	s := testStore(t)
	d, err := s.CreateDomain("a.test", "mail1", "PEM")
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.EnqueueEmail(&store.Email{
		DomainID: d.ID, From: "doevoe@a.test", To: "ops@a.test",
		Subject: "doevoe: monthly stats", BodyText: "…", IsSystem: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSent(id, store.Now()); err != nil {
		t.Fatal(err)
	}
	hook, _ := s.CreateWebhook("h", "https://recv.test/h", "sec", []string{EventEmailSent})

	(&Dispatcher{Store: s}).EmailEvent(EventEmailSent, id)

	deliveries, _ := s.ListWebhookDeliveries(hook.ID, 10)
	if len(deliveries) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(deliveries))
	}
	var got struct {
		Data struct {
			Email struct {
				System bool `json:"system"`
			} `json:"email"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(deliveries[0].Payload), &got); err != nil {
		t.Fatal(err)
	}
	if !got.Data.Email.System {
		t.Errorf("payload = %s, want system:true", deliveries[0].Payload)
	}
}

// A test delivery is addressed at one endpoint, so it must reach an endpoint
// that subscribes to nothing at all.
func TestTestEventIgnoresSubscriptions(t *testing.T) {
	s := testStore(t)
	hook, err := s.CreateWebhook("h", "https://recv.test/h", "sec", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Dispatcher{Store: s}).Test(hook.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ListWebhookDeliveries(hook.ID, 10); len(got) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(got))
	}
}

func TestTickPrunesOldHistoryOnce(t *testing.T) {
	s := testStore(t)
	hook, _ := s.CreateWebhook("h", "https://recv.test/h", "sec", []string{EventEmailSent})
	old := store.FmtTime(time.Now().Add(-30 * 24 * time.Hour))
	id, _ := s.EnqueueWebhookDelivery(&store.WebhookDelivery{
		WebhookID: hook.ID, Event: EventEmailSent, Payload: "{}", CreatedAt: old,
		NextAttemptAt: store.FmtTime(time.Now().Add(time.Hour)), // not due, so the tick won't send it
	})
	if err := s.MarkWebhookDelivered(id, 200, old); err != nil {
		t.Fatal(err)
	}
	if err := (&Dispatcher{Store: s}).Tick(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetWebhookDelivery(id); !store.IsNotFound(err) {
		t.Error("a finished delivery older than the retention window must be pruned")
	}
}

func TestNextAttempt(t *testing.T) {
	now := time.Now()
	if got, ok := NextAttempt(1, now); !ok || got != now.Add(Schedule[0]) {
		t.Errorf("NextAttempt(1) = %v, %v", got, ok)
	}
	if _, ok := NextAttempt(len(Schedule)+1, now); ok {
		t.Error("retries must be exhausted past the schedule")
	}
	if _, ok := NextAttempt(0, now); ok {
		t.Error("attempt 0 is not a thing")
	}
}
