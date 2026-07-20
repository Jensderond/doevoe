package delivery

import (
	"context"
	"path/filepath"
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
