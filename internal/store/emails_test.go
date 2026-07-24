package store

import (
	"errors"
	"testing"
	"time"
)

func enqueueTest(t *testing.T, s *Store, domainID int64, to string) int64 {
	t.Helper()
	id, err := s.EnqueueEmail(&Email{DomainID: domainID, From: "a@example.com", To: to, Subject: "hi", BodyText: "yo"})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestClaimDueIsExclusive(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id := enqueueTest(t, s, d.ID, "u@dest.test")

	claimed, err := s.ClaimDue(10, Now())
	if err != nil || len(claimed) != 1 || claimed[0].ID != id {
		t.Fatalf("first claim: %v %v", claimed, err)
	}
	again, _ := s.ClaimDue(10, Now())
	if len(again) != 0 {
		t.Fatal("second claim must be empty (status=sending)")
	}
}

func TestRetryAndFailLifecycle(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id := enqueueTest(t, s, d.ID, "u@dest.test")
	s.ClaimDue(1, Now())

	if err := s.MarkRetry(id, "2999-01-01T00:00:00Z", "451 try later"); err != nil {
		t.Fatal(err)
	}
	e, _ := s.GetEmail(id)
	if e.Status != "queued" || e.Attempts != 1 || e.LastError != "451 try later" {
		t.Fatalf("after retry: %+v", e)
	}
	if got, _ := s.ClaimDue(1, Now()); len(got) != 0 {
		t.Fatal("future next_attempt_at must not be claimable")
	}
	s.db.Exec(`UPDATE emails SET status='sending' WHERE id=?`, id)
	if err := s.MarkFailed(id, "550 no such user"); err != nil {
		t.Fatal(err)
	}
	e, _ = s.GetEmail(id)
	if e.Status != "failed" || e.Attempts != 2 {
		t.Fatalf("after fail: %+v", e)
	}
}

func TestRequeueWithRecipientEdit(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id := enqueueTest(t, s, d.ID, "u@gmial.com")
	s.db.Exec(`UPDATE emails SET status='failed', attempts=3 WHERE id=?`, id)

	if err := s.RequeueEmail(id, "u@gmail.com", ""); err != nil {
		t.Fatal(err)
	}
	e, _ := s.GetEmail(id)
	if e.To != "u@gmail.com" || e.OriginalTo != "u@gmial.com" || e.Status != "queued" || e.Attempts != 0 {
		t.Fatalf("after requeue: %+v", e)
	}
}

func TestRequeuePreservesDisplayNameEdit(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id := enqueueTest(t, s, d.ID, "u@example.com")
	s.db.Exec(`UPDATE emails SET status='failed', to_name='Jenny' WHERE id=?`, id)

	// A display-name-only edit is not a re-addressing, so original_to stays empty.
	if err := s.RequeueEmail(id, "u@example.com", "Jens"); err != nil {
		t.Fatal(err)
	}
	e, _ := s.GetEmail(id)
	if e.ToName != "Jens" || e.OriginalTo != "" {
		t.Fatalf("after name-only requeue: to_name=%q original_to=%q", e.ToName, e.OriginalTo)
	}
}

func TestCancelEmail(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id := enqueueTest(t, s, d.ID, "u@dest.test")
	s.MarkRetry(id, FmtTime(time.Now().Add(time.Hour)), "dial tcp :25: connect: connection refused")

	if err := s.CancelEmail(id); err != nil {
		t.Fatal(err)
	}
	e, _ := s.GetEmail(id)
	if e.Status != "canceled" {
		t.Fatalf("status = %q, want canceled", e.Status)
	}
	// The failure that prompted the cancel must survive, so the admin page can
	// still show why the email was abandoned.
	if e.LastError == "" {
		t.Error("last_error should be preserved on cancel")
	}
	// A canceled email is out of the delivery pipeline for good.
	if _, err := s.db.Exec(`UPDATE emails SET next_attempt_at=? WHERE id=?`, Now(), id); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.ClaimDue(10, Now()); len(got) != 0 {
		t.Fatalf("canceled email must not be claimable, got %d", len(got))
	}
	// Cancelling again is refused rather than silently succeeding.
	if err := s.CancelEmail(id); !errors.Is(err, ErrNotCancelable) {
		t.Fatalf("second cancel: got %v, want ErrNotCancelable", err)
	}
}

func TestCancelAndRequeueGuardsAgainstSending(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id := enqueueTest(t, s, d.ID, "u@dest.test")
	if claimed, _ := s.ClaimDue(1, Now()); len(claimed) != 1 {
		t.Fatal("email should have been claimed")
	}

	// Mid-delivery: neither action may touch the row, or the worker's own
	// outcome write would clobber it (or resurrect a canceled email).
	if err := s.CancelEmail(id); !errors.Is(err, ErrNotCancelable) {
		t.Fatalf("cancel while sending: got %v, want ErrNotCancelable", err)
	}
	if err := s.RequeueEmail(id, "fixed@dest.test", ""); !errors.Is(err, ErrNotRequeueable) {
		t.Fatalf("requeue while sending: got %v, want ErrNotRequeueable", err)
	}
	e, _ := s.GetEmail(id)
	if e.Status != "sending" || e.To != "u@dest.test" {
		t.Fatalf("row changed despite guard: %+v", e)
	}
}

func TestRequeueFromCanceledAndQueued(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")

	// A canceled email can be resumed after the operator fixes the address.
	canceledID := enqueueTest(t, s, d.ID, "u@wrong.test")
	if err := s.CancelEmail(canceledID); err != nil {
		t.Fatal(err)
	}
	if err := s.RequeueEmail(canceledID, "u@right.test", ""); err != nil {
		t.Fatalf("requeue canceled: %v", err)
	}
	if e, _ := s.GetEmail(canceledID); e.Status != "queued" || e.To != "u@right.test" || e.OriginalTo != "u@wrong.test" {
		t.Fatalf("after requeue of canceled: %+v", e)
	}

	// A queued email still waiting out its backoff can be re-addressed and sent now.
	queuedID := enqueueTest(t, s, d.ID, "v@wrong.test")
	s.MarkRetry(queuedID, FmtTime(time.Now().Add(4*time.Hour)), "451 later")
	if err := s.RequeueEmail(queuedID, "v@right.test", ""); err != nil {
		t.Fatalf("requeue queued: %v", err)
	}
	e, _ := s.GetEmail(queuedID)
	if e.Attempts != 0 || e.LastError != "" || e.To != "v@right.test" {
		t.Fatalf("after requeue of queued: %+v", e)
	}
	// Both requeued emails are due right away rather than keeping their old
	// next_attempt_at.
	claimed, _ := s.ClaimDue(10, Now())
	due := map[int64]bool{}
	for _, c := range claimed {
		due[c.ID] = true
	}
	if !due[queuedID] || !due[canceledID] {
		t.Fatalf("requeued emails should be immediately due, claimed %v", due)
	}

	// A sent email is never requeueable — no double delivery.
	sentID := enqueueTest(t, s, d.ID, "w@dest.test")
	s.MarkSent(sentID, Now())
	if err := s.RequeueEmail(sentID, "", ""); !errors.Is(err, ErrNotRequeueable) {
		t.Fatalf("requeue sent: got %v, want ErrNotRequeueable", err)
	}
}

func TestRequeueStaleSending(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	staleID := enqueueTest(t, s, d.ID, "stale@dest.test")
	freshID := enqueueTest(t, s, d.ID, "fresh@dest.test")

	claimed, err := s.ClaimDue(10, Now())
	if err != nil || len(claimed) != 2 {
		t.Fatalf("claim: %v %v", claimed, err)
	}

	// Backdate the stale email's next_attempt_at (stamped at claim time) by 20m
	// so it looks like it's been stuck in 'sending' for a while.
	backdated := FmtTime(time.Now().Add(-20 * time.Minute))
	if _, err := s.db.Exec(`UPDATE emails SET next_attempt_at=? WHERE id=?`, backdated, staleID); err != nil {
		t.Fatal(err)
	}

	cutoff := FmtTime(time.Now().Add(-15 * time.Minute))
	n, err := s.RequeueStaleSending(cutoff)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("want 1 requeued, got %d", n)
	}

	stale, _ := s.GetEmail(staleID)
	if stale.Status != "queued" {
		t.Errorf("stale email should be requeued: %+v", stale)
	}
	fresh, _ := s.GetEmail(freshID)
	if fresh.Status != "sending" {
		t.Errorf("freshly claimed email must not be requeued: %+v", fresh)
	}
}

func TestEnqueueHonorsExplicitCreatedAt(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, err := s.EnqueueEmail(&Email{DomainID: d.ID, From: "a@example.com", To: "u@dest.test",
		Subject: "s", BodyText: "b", CreatedAt: "2026-05-10T08:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	e, _ := s.GetEmail(id)
	if e.CreatedAt != "2026-05-10T08:00:00Z" {
		t.Fatalf("created_at not honored: %q", e.CreatedAt)
	}
}

func TestListEmailsDateRange(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	for _, ts := range []string{"2026-07-01T10:00:00Z", "2026-07-10T10:00:00Z", "2026-07-20T10:00:00Z"} {
		if _, err := s.EnqueueEmail(&Email{DomainID: d.ID, From: "a@example.com", To: "u-" + ts[8:10] + "@dest.test",
			Subject: "s", BodyText: "b", CreatedAt: ts}); err != nil {
			t.Fatal(err)
		}
	}

	got, err := s.ListEmails(EmailFilter{CreatedFrom: "2026-07-05T00:00:00Z", CreatedTo: "2026-07-15T00:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].To != "u-10@dest.test" {
		t.Fatalf("range filter: want only u-10, got %+v", got)
	}

	// Boundaries: CreatedFrom is inclusive, CreatedTo is exclusive.
	got, _ = s.ListEmails(EmailFilter{CreatedFrom: "2026-07-10T10:00:00Z", CreatedTo: "2026-07-20T10:00:00Z"})
	if len(got) != 1 || got[0].To != "u-10@dest.test" {
		t.Fatalf("boundary semantics: want only u-10, got %+v", got)
	}

	// One-sided filters and combination with other filters.
	if got, _ = s.ListEmails(EmailFilter{CreatedFrom: "2026-07-15T00:00:00Z"}); len(got) != 1 || got[0].To != "u-20@dest.test" {
		t.Fatalf("from-only: want only u-20, got %+v", got)
	}
	if got, _ = s.ListEmails(EmailFilter{CreatedTo: "2026-07-05T00:00:00Z"}); len(got) != 1 || got[0].To != "u-01@dest.test" {
		t.Fatalf("to-only: want only u-01, got %+v", got)
	}
	if got, _ = s.ListEmails(EmailFilter{Status: "sent", CreatedFrom: "2026-07-05T00:00:00Z"}); len(got) != 0 {
		t.Fatalf("combined with status: want none, got %+v", got)
	}
}

func TestIdempotency(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	kid, _ := s.CreateAPIKey("k", d.ID, "h")
	e := &Email{APIKeyID: kid, DomainID: d.ID, From: "a@example.com", To: "b@dest.test", Subject: "s", BodyText: "t", IdempotencyKey: "abc"}
	id1, err := s.EnqueueEmail(e)
	if err != nil {
		t.Fatal(err)
	}
	found, err := s.FindByIdempotencyKey(kid, "abc")
	if err != nil || found == nil || found.ID != id1 {
		t.Fatalf("idempotency lookup: %+v %v", found, err)
	}
}

func TestDisplayNameRoundTrip(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, err := s.EnqueueEmail(&Email{DomainID: d.ID, From: "a@example.com", To: "b@dest.test",
		FromName: "Atelier Cornelia", ToName: "Jens de Rond", Subject: "hi", BodyText: "yo"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.GetEmail(id)
	if err != nil {
		t.Fatal(err)
	}
	if e.FromName != "Atelier Cornelia" || e.ToName != "Jens de Rond" {
		t.Fatalf("names not round-tripped: from=%q to=%q", e.FromName, e.ToName)
	}
}
