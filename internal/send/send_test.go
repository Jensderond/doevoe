package send

import (
	"path/filepath"
	"testing"

	"doevoe/internal/store"
)

func setup(t *testing.T, verified bool) (*store.Store, *store.Domain, *store.APIKey) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	d, err := s.CreateDomain("example.com", "mail1", "PEM")
	if err != nil {
		t.Fatal(err)
	}
	if verified {
		s.SetDomainVerification(d.ID, true, true, true, store.Now())
		d, _ = s.GetDomain(d.ID)
	}
	_, hash, err := store.GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.CreateAPIKey("test", d.ID, hash)
	if err != nil {
		t.Fatal(err)
	}
	return s, d, &store.APIKey{ID: id, DomainID: d.ID}
}

func TestSendEnqueues(t *testing.T) {
	s, d, k := setup(t, true)
	res, serr := Send(s, k.ID, d.ID, Input{
		From: "hi@example.com", To: "you@other.com", Subject: "s", Text: "b",
	})
	if serr != nil {
		t.Fatalf("unexpected error: %v", serr)
	}
	if res.Status != "queued" || res.Replay || res.ID == 0 {
		t.Fatalf("got %+v", res)
	}
	e, err := s.GetEmail(res.ID)
	if err != nil || e.From != "hi@example.com" {
		t.Fatalf("stored email: %+v err=%v", e, err)
	}
}

func TestSendUnverifiedDomainFailsClosed(t *testing.T) {
	s, d, k := setup(t, false)
	_, serr := Send(s, k.ID, d.ID, Input{
		From: "hi@example.com", To: "you@other.com", Subject: "s", Text: "b",
	})
	if serr == nil || serr.Code != 403 {
		t.Fatalf("want 403, got %+v", serr)
	}
}

func TestSendWrongFromDomain(t *testing.T) {
	s, d, k := setup(t, true)
	_, serr := Send(s, k.ID, d.ID, Input{
		From: "hi@elsewhere.com", To: "you@other.com", Subject: "s", Text: "b",
	})
	if serr == nil || serr.Code != 422 {
		t.Fatalf("want 422, got %+v", serr)
	}
}

// TestEnqueueOrReplayRecoversFromIndexRace covers the handler-recovery half
// of Finding 2 (moved here with enqueueOrReplay from internal/api).
// Deterministically driving the actual concurrent race through the HTTP
// handler isn't reproducible without flakiness (the whole point is that
// both requests pass the pre-check before either inserts), so this instead
// unit-tests the enqueueOrReplay helper directly: it pre-creates a row with
// idempotency key K (standing in for the racing request that won), then
// calls enqueueOrReplay with a second, distinct Email that reuses the same
// (api_key_id, idempotency_key) pair (standing in for the request that lost
// the race and whose EnqueueEmail call fails against idx_emails_idem). The
// helper must recover by finding the winning row and returning it as a
// replay, not surface the raw insert error as a 500.
func TestEnqueueOrReplayRecoversFromIndexRace(t *testing.T) {
	s, d, k := setup(t, true)

	winner := &store.Email{APIKeyID: k.ID, DomainID: d.ID, From: "info@example.com", To: "u@dest.test",
		Subject: "s", BodyText: "t", IdempotencyKey: "race-key"}
	winnerID, err := s.EnqueueEmail(winner)
	if err != nil {
		t.Fatalf("seed winning insert: %v", err)
	}

	loser := &store.Email{APIKeyID: k.ID, DomainID: d.ID, From: "info@example.com", To: "other@dest.test",
		Subject: "s2", BodyText: "t2", IdempotencyKey: "race-key"}
	id, status, replay, err := enqueueOrReplay(s, loser)
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

func TestSendIdempotentReplay(t *testing.T) {
	s, d, k := setup(t, true)
	in := Input{From: "hi@example.com", To: "you@other.com", Subject: "s", Text: "b", IdempotencyKey: "abc"}
	first, serr := Send(s, k.ID, d.ID, in)
	if serr != nil {
		t.Fatal(serr)
	}
	second, serr := Send(s, k.ID, d.ID, in)
	if serr != nil {
		t.Fatal(serr)
	}
	if !second.Replay || second.ID != first.ID {
		t.Fatalf("want replay of %d, got %+v", first.ID, second)
	}
}
