package store

import (
	"path/filepath"
	"testing"
)

func blStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRecordBlocklistCheckTransitions(t *testing.T) {
	s := blStore(t)

	// First sight, clean: status row, no event, no transition.
	tr, err := s.RecordBlocklistCheck("203.0.113.7", "zen.spamhaus.org", false, "2026-08-01T10:00:00Z")
	if err != nil || tr != "" {
		t.Fatalf("first clean check: transition=%q err=%v, want \"\" nil", tr, err)
	}
	// Steady state: still no transition, last_checked advances.
	tr, _ = s.RecordBlocklistCheck("203.0.113.7", "zen.spamhaus.org", false, "2026-08-01T11:00:00Z")
	if tr != "" {
		t.Fatalf("steady clean: transition=%q, want \"\"", tr)
	}
	// Gets listed: transition + event.
	tr, _ = s.RecordBlocklistCheck("203.0.113.7", "zen.spamhaus.org", true, "2026-08-01T12:00:00Z")
	if tr != "listed" {
		t.Fatalf("newly listed: transition=%q, want \"listed\"", tr)
	}
	// Still listed: steady state again.
	tr, _ = s.RecordBlocklistCheck("203.0.113.7", "zen.spamhaus.org", true, "2026-08-01T13:00:00Z")
	if tr != "" {
		t.Fatalf("steady listed: transition=%q, want \"\"", tr)
	}
	// Cleared.
	tr, _ = s.RecordBlocklistCheck("203.0.113.7", "zen.spamhaus.org", false, "2026-08-01T14:00:00Z")
	if tr != "cleared" {
		t.Fatalf("cleared: transition=%q, want \"cleared\"", tr)
	}

	sts, err := s.ListBlocklistStatus()
	if err != nil || len(sts) != 1 {
		t.Fatalf("status rows: %v err=%v, want exactly 1", sts, err)
	}
	st := sts[0]
	if st.Listed || st.Since != "2026-08-01T14:00:00Z" || st.LastChecked != "2026-08-01T14:00:00Z" {
		t.Errorf("status = %+v; want unlisted, since/last_checked at the clear time", st)
	}

	evs, err := s.RecentBlocklistEvents(10)
	if err != nil || len(evs) != 2 {
		t.Fatalf("events: %v err=%v, want exactly 2 (listed, cleared)", evs, err)
	}
	// Newest first.
	if evs[0].Listed || !evs[1].Listed {
		t.Errorf("event order/content wrong: %+v", evs)
	}
	if evs[1].OccurredAt != "2026-08-01T12:00:00Z" || evs[0].OccurredAt != "2026-08-01T14:00:00Z" {
		t.Errorf("event timestamps wrong: %+v", evs)
	}
}

func TestRecordBlocklistCheckFirstSightListed(t *testing.T) {
	s := blStore(t)
	// First-ever check already listed must alert (transition "listed"):
	// the operator has never been told about this listing.
	tr, err := s.RecordBlocklistCheck("bad.example", "dbl.spamhaus.org", true, "2026-08-01T10:00:00Z")
	if err != nil || tr != "listed" {
		t.Fatalf("first-sight listed: transition=%q err=%v, want \"listed\" nil", tr, err)
	}
	evs, _ := s.RecentBlocklistEvents(10)
	if len(evs) != 1 || !evs[0].Listed {
		t.Fatalf("want one listed event, got %+v", evs)
	}
}

func TestListBlocklistStatusOrdersListedFirst(t *testing.T) {
	s := blStore(t)
	s.RecordBlocklistCheck("a.example", "multi.surbl.org", false, "2026-08-01T10:00:00Z")
	s.RecordBlocklistCheck("z.example", "dbl.spamhaus.org", true, "2026-08-01T10:00:00Z")
	sts, err := s.ListBlocklistStatus()
	if err != nil || len(sts) != 2 {
		t.Fatalf("got %v err=%v", sts, err)
	}
	if !sts[0].Listed {
		t.Errorf("listed rows must sort first: %+v", sts)
	}
}
