package delivery

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"doevoe/internal/store"

	"github.com/emersion/go-smtp"
)

type fakeSend struct {
	mu      sync.Mutex
	results map[string]Result // keyed by recipient
	calls   []string
}

func (f *fakeSend) send(_ context.Context, e *store.Email, _ *store.Domain) Result {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, e.To)
	return f.results[e.To]
}

func workerFixture(t *testing.T) (*store.Store, *fakeSend, *Worker, []int64) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	var ids []int64
	for _, to := range []string{"ok@dest.test", "temp@dest.test", "perm@dest.test"} {
		id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: to, Subject: "s", BodyText: "b"})
		ids = append(ids, id)
	}
	f := &fakeSend{results: map[string]Result{
		"ok@dest.test":   {Code: 250},
		"temp@dest.test": {Code: 451, Err: &smtp.SMTPError{Code: 451, Message: "later"}},
		"perm@dest.test": {Code: 550, Err: &smtp.SMTPError{Code: 550, Message: "gone"}},
	}}
	w := &Worker{Store: s, Send: f.send, BatchSize: 10, PerDomainLimit: 2}
	return s, f, w, ids
}

func TestTickOutcomes(t *testing.T) {
	s, _, w, ids := workerFixture(t)
	var permFailed []int64
	w.OnPermanentFailure = func(id int64) { permFailed = append(permFailed, id) }

	if err := w.Tick(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	ok, _ := s.GetEmail(ids[0])
	temp, _ := s.GetEmail(ids[1])
	perm, _ := s.GetEmail(ids[2])
	if ok.Status != "sent" {
		t.Errorf("ok: %+v", ok)
	}
	if temp.Status != "queued" || temp.Attempts != 1 || temp.NextAttemptAt <= store.Now() {
		t.Errorf("temp must be requeued in the future: %+v", temp)
	}
	if perm.Status != "failed" {
		t.Errorf("perm: %+v", perm)
	}
	if len(permFailed) != 1 || permFailed[0] != ids[2] {
		t.Errorf("OnPermanentFailure calls: %v", permFailed)
	}
	attempts, _ := s.ListAttempts(ids[2])
	if len(attempts) != 1 || attempts[0].SMTPCode != 550 {
		t.Errorf("attempt rows: %+v", attempts)
	}
}

// OnSent must fire once per delivered email, and only after MarkSent, so a
// hook that reads the email back (the webhook dispatcher does) sees 'sent'.
func TestOnSentFiresAfterStatusIsWritten(t *testing.T) {
	s, _, w, ids := workerFixture(t)
	var mu sync.Mutex
	var sent []int64
	statuses := map[int64]string{}
	w.OnSent = func(id int64) {
		e, err := s.GetEmail(id)
		if err != nil {
			t.Errorf("hook could not load email %d: %v", id, err)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, id)
		statuses[id] = e.Status
	}

	if err := w.Tick(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 1 || sent[0] != ids[0] {
		t.Fatalf("OnSent calls = %v, want just the delivered email %d", sent, ids[0])
	}
	if statuses[ids[0]] != "sent" {
		t.Errorf("status seen by the hook = %q, want sent", statuses[ids[0]])
	}
}

func TestPerDomainLimitCapsConcurrency(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")

	const n = 6
	const limit = 2
	for i := 0; i < n; i++ {
		to := "u" + string(rune('a'+i)) + "@dest.test"
		if _, err := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: to, Subject: "s", BodyText: "b"}); err != nil {
			t.Fatal(err)
		}
	}

	var mu sync.Mutex
	inFlight := 0
	maxInFlight := 0
	send := func(_ context.Context, e *store.Email, _ *store.Domain) Result {
		mu.Lock()
		inFlight++
		if inFlight > maxInFlight {
			maxInFlight = inFlight
		}
		mu.Unlock()

		time.Sleep(50 * time.Millisecond)

		mu.Lock()
		inFlight--
		mu.Unlock()
		return Result{Code: 250}
	}

	w := &Worker{Store: s, Send: send, BatchSize: n, PerDomainLimit: limit}
	if err := w.Tick(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	got := maxInFlight
	mu.Unlock()
	if got > limit {
		t.Fatalf("max in-flight sends %d exceeded PerDomainLimit %d", got, limit)
	}
	if got == 0 {
		t.Fatal("expected at least one send to have run")
	}
}

func TestPanicInSendIsRecoveredAndQueuedForRetry(t *testing.T) {
	s, f, w, ids := workerFixture(t)

	w.Send = func(ctx context.Context, e *store.Email, d *store.Domain) Result {
		if e.To == "ok@dest.test" {
			panic("boom")
		}
		return f.send(ctx, e, d)
	}

	if err := w.Tick(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}

	panicked, err := s.GetEmail(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if panicked.Status != "queued" || panicked.Attempts != 1 {
		t.Fatalf("panicking send should leave email queued with attempts=1: %+v", panicked)
	}
	if !strings.Contains(panicked.LastError, "panic:") {
		t.Errorf("last_error should mention the panic: %q", panicked.LastError)
	}
	if panicked.NextAttemptAt <= store.Now() {
		t.Errorf("panicking email must be rescheduled in the future: %+v", panicked)
	}

	// The rest of the batch (unaffected by the panic) must still be processed
	// normally, proving the tick survives one goroutine panicking.
	temp, _ := s.GetEmail(ids[1])
	if temp.Status != "queued" || temp.Attempts != 1 {
		t.Errorf("other emails in the batch must still be processed: %+v", temp)
	}
	perm, _ := s.GetEmail(ids[2])
	if perm.Status != "failed" {
		t.Errorf("other emails in the batch must still be processed: %+v", perm)
	}
}

func TestExhaustedRetriesFail(t *testing.T) {
	s, _, w, _ := workerFixture(t)
	d, _ := s.CreateDomain("other.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@other.com", To: "temp@dest.test", Subject: "s", BodyText: "b"})
	// simulate 7 prior attempts
	for i := 0; i < 7; i++ {
		s.ClaimDue(100, store.Now())
		s.MarkRetry(id, store.Now(), "451")
	}
	var permFailed []int64
	w.OnPermanentFailure = func(eid int64) { permFailed = append(permFailed, eid) }
	if err := w.Tick(context.Background(), time.Now()); err != nil {
		t.Fatal(err)
	}
	e, _ := s.GetEmail(id)
	if e.Status != "failed" {
		t.Fatalf("want failed after exhausting schedule: %+v", e)
	}
	found := false
	for _, eid := range permFailed {
		if eid == id {
			found = true
		}
	}
	if !found {
		t.Fatal("OnPermanentFailure not called for exhausted email")
	}
}
