package store

import (
	"strings"
	"testing"
	"time"
)

func createTestWebhook(t *testing.T, s *Store, events ...string) *Webhook {
	t.Helper()
	w, err := s.CreateWebhook("hook", "https://recv.test/hook", "whsec_x", events)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func TestWebhookRoundTrip(t *testing.T) {
	s := testStore(t)
	w := createTestWebhook(t, s, "email.sent", "email.failed")
	if !w.Active {
		t.Error("new webhooks must be active")
	}
	if len(w.Events) != 2 || w.Events[0] != "email.sent" {
		t.Fatalf("events = %v", w.Events)
	}
	if !w.Subscribed("email.failed") || w.Subscribed("domain.verified") {
		t.Error("Subscribed must match exact event names")
	}

	if err := s.UpdateWebhook(w.ID, "renamed", "https://other.test/h", []string{"domain.verified"}, false); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetWebhook(w.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "renamed" || got.URL != "https://other.test/h" || got.Active {
		t.Fatalf("after update: %+v", got)
	}
	if len(got.Events) != 1 || got.Events[0] != "domain.verified" {
		t.Fatalf("events after update: %v", got.Events)
	}
	if got.Secret != "whsec_x" {
		t.Error("update must not disturb the signing secret")
	}
}

func TestListActiveWebhooksForEvent(t *testing.T) {
	s := testStore(t)
	subscribed := createTestWebhook(t, s, "email.sent")
	other := createTestWebhook(t, s, "email.failed")
	paused := createTestWebhook(t, s, "email.sent")
	if err := s.UpdateWebhook(paused.ID, paused.Name, paused.URL, paused.Events, false); err != nil {
		t.Fatal(err)
	}

	hooks, err := s.ListActiveWebhooksForEvent("email.sent")
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 1 || hooks[0].ID != subscribed.ID {
		t.Fatalf("hooks = %+v, want only the active subscriber %d (not %d/%d)",
			hooks, subscribed.ID, other.ID, paused.ID)
	}
}

// A LIKE-based subscription filter would match one event name inside another;
// membership must be exact.
func TestListActiveWebhooksForEventIsExact(t *testing.T) {
	s := testStore(t)
	createTestWebhook(t, s, "email.sent_to_archive")
	hooks, err := s.ListActiveWebhooksForEvent("email.sent")
	if err != nil {
		t.Fatal(err)
	}
	if len(hooks) != 0 {
		t.Fatalf("hooks = %+v, want none", hooks)
	}
}

func TestWebhookDeliveryLifecycle(t *testing.T) {
	s := testStore(t)
	w := createTestWebhook(t, s, "email.sent")
	id, err := s.EnqueueWebhookDelivery(&WebhookDelivery{
		WebhookID: w.ID, EmailID: 7, Event: "email.sent", Payload: `{"event":"email.sent"}`,
	})
	if err != nil {
		t.Fatal(err)
	}

	claimed, err := s.ClaimDueWebhookDeliveries(10, Now())
	if err != nil || len(claimed) != 1 || claimed[0].ID != id {
		t.Fatalf("first claim: %+v %v", claimed, err)
	}
	if claimed[0].EmailID != 7 || claimed[0].Payload != `{"event":"email.sent"}` {
		t.Fatalf("claimed row lost data: %+v", claimed[0])
	}
	if again, _ := s.ClaimDueWebhookDeliveries(10, Now()); len(again) != 0 {
		t.Fatal("second claim must be empty (status=sending)")
	}

	if err := s.MarkWebhookDeliveryRetry(id, FmtTime(time.Now().Add(time.Hour)), 502, "HTTP 502"); err != nil {
		t.Fatal(err)
	}
	d, _ := s.GetWebhookDelivery(id)
	if d.Status != "queued" || d.Attempts != 1 || d.ResponseCode != 502 || d.LastError != "HTTP 502" {
		t.Fatalf("after retry: %+v", d)
	}
	if got, _ := s.ClaimDueWebhookDeliveries(10, Now()); len(got) != 0 {
		t.Fatal("a future next_attempt_at must not be claimable")
	}

	if err := s.MarkWebhookDelivered(id, 200, Now()); err != nil {
		t.Fatal(err)
	}
	d, _ = s.GetWebhookDelivery(id)
	if d.Status != "delivered" || d.Attempts != 2 || d.ResponseCode != 200 || d.LastError != "" || d.DeliveredAt == "" {
		t.Fatalf("after delivered: %+v", d)
	}
}

func TestRequeueStaleWebhookDeliveries(t *testing.T) {
	s := testStore(t)
	w := createTestWebhook(t, s, "email.sent")
	id, err := s.EnqueueWebhookDelivery(&WebhookDelivery{WebhookID: w.ID, Event: "email.sent", Payload: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimDueWebhookDeliveries(1, Now()); err != nil {
		t.Fatal(err)
	}
	// Not stale yet.
	if n, _ := s.RequeueStaleWebhookDeliveries(FmtTime(time.Now().Add(-time.Hour))); n != 0 {
		t.Fatalf("requeued %d rows, want 0", n)
	}
	n, err := s.RequeueStaleWebhookDeliveries(FmtTime(time.Now().Add(time.Hour)))
	if err != nil || n != 1 {
		t.Fatalf("requeue = %d, %v", n, err)
	}
	d, _ := s.GetWebhookDelivery(id)
	if d.Status != "queued" {
		t.Fatalf("status = %q, want queued", d.Status)
	}
}

func TestPruneWebhookDeliveriesKeepsInFlight(t *testing.T) {
	s := testStore(t)
	w := createTestWebhook(t, s, "email.sent")
	old := FmtTime(time.Now().Add(-30 * 24 * time.Hour))
	delivered, _ := s.EnqueueWebhookDelivery(&WebhookDelivery{WebhookID: w.ID, Event: "email.sent", Payload: "{}", CreatedAt: old})
	queued, _ := s.EnqueueWebhookDelivery(&WebhookDelivery{WebhookID: w.ID, Event: "email.sent", Payload: "{}", CreatedAt: old})
	recent, _ := s.EnqueueWebhookDelivery(&WebhookDelivery{WebhookID: w.ID, Event: "email.sent", Payload: "{}"})
	if err := s.MarkWebhookDelivered(delivered, 200, Now()); err != nil {
		t.Fatal(err)
	}

	n, err := s.PruneWebhookDeliveries(FmtTime(time.Now().Add(-14 * 24 * time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1 (only the old finished one)", n)
	}
	if _, err := s.GetWebhookDelivery(queued); err != nil {
		t.Error("an old but still-queued delivery must survive pruning")
	}
	if _, err := s.GetWebhookDelivery(recent); err != nil {
		t.Error("a recent delivery must survive pruning")
	}
}

func TestDeleteWebhookRemovesDeliveries(t *testing.T) {
	s := testStore(t)
	w := createTestWebhook(t, s, "email.sent")
	id, err := s.EnqueueWebhookDelivery(&WebhookDelivery{WebhookID: w.ID, Event: "email.sent", Payload: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteWebhook(w.ID); err != nil {
		t.Fatalf("delete with delivery history must succeed: %v", err)
	}
	if _, err := s.GetWebhook(w.ID); !IsNotFound(err) {
		t.Errorf("GetWebhook after delete: %v, want not-found", err)
	}
	if _, err := s.GetWebhookDelivery(id); !IsNotFound(err) {
		t.Errorf("delivery after delete: %v, want not-found", err)
	}
}

func TestTouchWebhook(t *testing.T) {
	s := testStore(t)
	w := createTestWebhook(t, s, "email.sent")
	at := Now()
	if err := s.TouchWebhook(w.ID, 500, "HTTP 500: boom", at); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetWebhook(w.ID)
	if got.LastStatus != 500 || got.LastError != "HTTP 500: boom" || got.LastDeliveryAt != at {
		t.Fatalf("after touch: %+v", got)
	}
}

func TestGenerateWebhookSecret(t *testing.T) {
	a, err := GenerateWebhookSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := GenerateWebhookSecret()
	if !strings.HasPrefix(a, "whsec_") {
		t.Errorf("secret = %q, want a whsec_ prefix", a)
	}
	if len(a) < 40 {
		t.Errorf("secret %q is too short to be a signing key", a)
	}
	if a == b {
		t.Error("secrets must not repeat")
	}
}
