package notify

import (
	"path/filepath"
	"testing"
	"time"

	"doevoe/internal/store"
)

func fixture(t *testing.T, systemVerified bool) (*store.Store, *Notifier, int64) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	sys, _ := s.CreateDomain("sys.example", "mail1", "PEM")
	if systemVerified {
		s.SetDomainVerification(sys.ID, true, true, true, store.Now())
	}
	client, _ := s.CreateDomain("client.example", "mail1", "PEM")
	n := &Notifier{Store: s, AdminEmail: "ops@example.com", SystemFrom: "noreply@sys.example",
		BaseURL: "https://doevoe.example", Threshold: 0.2, MinVolume: 10}
	return s, n, client.ID
}

func systemEmails(t *testing.T, s *store.Store) []*store.Email {
	t.Helper()
	all, err := s.ListEmails(store.EmailFilter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []*store.Email
	for _, e := range all {
		if e.IsSystem {
			out = append(out, e)
		}
	}
	return out
}

func failEmail(t *testing.T, s *store.Store, domainID int64, to string) int64 {
	t.Helper()
	id, _ := s.EnqueueEmail(&store.Email{DomainID: domainID, From: "a@client.example", To: to, Subject: "s", BodyText: "b"})
	s.MarkFailed(id, "550 no such user")
	return id
}

func TestDigestBatchesWithCooldown(t *testing.T) {
	s, n, clientID := fixture(t, true)
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	n.PermanentFailure(failEmail(t, s, clientID, "a@dest.test"))
	n.PermanentFailure(failEmail(t, s, clientID, "b@dest.test"))
	if err := n.DigestTick(now); err != nil {
		t.Fatal(err)
	}
	if got := systemEmails(t, s); len(got) != 1 {
		t.Fatalf("want 1 digest, got %d", len(got))
	}
	if pending, _ := s.ListPendingFailures(); len(pending) != 0 {
		t.Fatal("pending must be cleared after digest")
	}

	n.PermanentFailure(failEmail(t, s, clientID, "c@dest.test"))
	n.DigestTick(now.Add(5 * time.Minute)) // inside cooldown
	if got := systemEmails(t, s); len(got) != 1 {
		t.Fatal("cooldown violated")
	}
	n.DigestTick(now.Add(2 * time.Hour))
	if got := systemEmails(t, s); len(got) != 2 {
		t.Fatal("second digest expected after cooldown")
	}
}

func TestDigestSkipsWhenSystemDomainUnverified(t *testing.T) {
	s, n, clientID := fixture(t, false)
	n.PermanentFailure(failEmail(t, s, clientID, "a@dest.test"))
	if err := n.DigestTick(time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := systemEmails(t, s); len(got) != 0 {
		t.Fatal("must not enqueue via unverified system domain")
	}
	if pending, _ := s.ListPendingFailures(); len(pending) != 1 {
		t.Fatal("pending must be kept for later")
	}
}

func TestSystemFailuresNeverNotify(t *testing.T) {
	s, n, _ := fixture(t, true)
	sys, _ := s.GetDomainByName("sys.example")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: sys.ID, From: "noreply@sys.example",
		To: "ops@example.com", Subject: "alert", BodyText: "b", IsSystem: true})
	s.MarkFailed(id, "451")
	n.PermanentFailure(id)
	if pending, _ := s.ListPendingFailures(); len(pending) != 0 {
		t.Fatal("system email failure must not create pending notification (loop guard)")
	}
}

func TestRateAlertFiresOncePerIncident(t *testing.T) {
	s, n, clientID := fixture(t, true)
	now := time.Now().UTC()
	for i := 0; i < 10; i++ {
		id := failEmail(t, s, clientID, "x@dest.test")
		code := 250
		if i < 5 {
			code = 451
		}
		s.RecordAttempt(id, 1, code, "mx", "resp", 10)
	}
	n.RateTick(now)
	n.RateTick(now)
	if got := systemEmails(t, s); len(got) != 1 {
		t.Fatalf("want exactly 1 rate alert, got %d", len(got))
	}
}

func TestMonthlyStats(t *testing.T) {
	s, n, clientID := fixture(t, true)
	jul := time.Date(2026, 7, 20, 9, 0, 0, 0, time.UTC)

	// fresh install: initialize, don't send
	n.StatsTick(jul)
	if got := systemEmails(t, s); len(got) != 0 {
		t.Fatal("no phantom report on fresh install")
	}
	// activity in July
	id := failEmail(t, s, clientID, "x@dest.test")
	_ = id
	// month rolls over
	aug := time.Date(2026, 8, 1, 0, 30, 0, 0, time.UTC)
	n.StatsTick(aug)
	got := systemEmails(t, s)
	if len(got) != 1 {
		t.Fatalf("want stats email, got %d", len(got))
	}
	if v, _ := s.GetState("last_stats_sent"); v != "2026-08" {
		t.Fatalf("state: %q", v)
	}
	n.StatsTick(aug.Add(time.Hour))
	if got := systemEmails(t, s); len(got) != 1 {
		t.Fatal("stats must send once per month")
	}
}
