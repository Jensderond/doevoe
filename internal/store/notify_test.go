package store

import "testing"

func TestStateAndPendingFailures(t *testing.T) {
	s := testStore(t)
	if v, _ := s.GetState("nope"); v != "" {
		t.Fatal("unset state must be empty")
	}
	s.SetState("k", "v1")
	s.SetState("k", "v2")
	if v, _ := s.GetState("k"); v != "v2" {
		t.Fatal("upsert failed")
	}

	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id := enqueueTest(t, s, d.ID, "u@dest.test")
	s.AddPendingFailure(id)
	s.AddPendingFailure(id) // duplicate must not error
	pending, err := s.ListPendingFailures()
	if err != nil || len(pending) != 1 || pending[0].ID != id {
		t.Fatalf("pending: %v %v", pending, err)
	}
	s.ClearPendingFailures()
	if pending, _ := s.ListPendingFailures(); len(pending) != 0 {
		t.Fatal("clear failed")
	}
}

func TestMonthlyStats(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id1 := enqueueTest(t, s, d.ID, "a@dest.test")
	id2 := enqueueTest(t, s, d.ID, "b@dest.test")
	s.db.Exec(`UPDATE emails SET status='sent', created_at='2026-06-05T10:00:00Z' WHERE id=?`, id1)
	s.db.Exec(`UPDATE emails SET status='failed', created_at='2026-06-06T10:00:00Z' WHERE id=?`, id2)

	stats, err := s.MonthlyStats("2026-06")
	if err != nil || len(stats) != 1 || stats[0].Sent != 1 || stats[0].Failed != 1 {
		t.Fatalf("stats: %+v %v", stats, err)
	}
}
