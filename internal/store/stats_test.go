package store

import "testing"

func insertEmail(t *testing.T, s *Store, domainID int64, status, createdAt, lastErr string) {
	t.Helper()
	_, err := s.db.Exec(`INSERT INTO emails
		(domain_id, from_addr, to_addr, subject, status, next_attempt_at, last_error, created_at)
		VALUES (?, 'from@x.test', 'to@y.test', 'subj', ?, ?, ?, ?)`,
		domainID, status, createdAt, lastErr, createdAt)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDailyVolumeBuckets(t *testing.T) {
	s := testStore(t)
	d, err := s.CreateDomain("a.test", "mail1", "pk")
	if err != nil {
		t.Fatal(err)
	}
	insertEmail(t, s, d.ID, "sent", "2026-07-01T10:00:00Z", "")
	insertEmail(t, s, d.ID, "sent", "2026-07-01T11:00:00Z", "")
	insertEmail(t, s, d.ID, "failed", "2026-07-02T09:00:00Z", "boom")
	got, err := s.DailyVolume("2026-07-01T00:00:00Z", "2026-07-03T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 days, got %d (%+v)", len(got), got)
	}
	if got[0].Date != "2026-07-01" || got[0].Sent != 2 || got[0].Failed != 0 {
		t.Errorf("day0 = %+v", got[0])
	}
	if got[1].Date != "2026-07-02" || got[1].Failed != 1 {
		t.Errorf("day1 = %+v", got[1])
	}
}

func TestSummaryStats(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("a.test", "mail1", "pk")
	insertEmail(t, s, d.ID, "sent", "2026-07-01T10:00:00Z", "")
	insertEmail(t, s, d.ID, "failed", "2026-07-01T10:00:00Z", "boom")
	insertEmail(t, s, d.ID, "queued", "2026-07-01T10:00:00Z", "")
	sm, err := s.SummaryStats("2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if sm.Sent != 1 || sm.Failed != 1 || sm.Queued != 1 || sm.Total != 3 {
		t.Errorf("summary = %+v", sm)
	}
	if sm.SuccessRate < 33.3 || sm.SuccessRate > 33.4 {
		t.Errorf("success rate = %v, want ~33.33", sm.SuccessRate)
	}
}

func TestSummaryStatsExcludesCanceledFromRate(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("a.test", "mail1", "pk")
	insertEmail(t, s, d.ID, "sent", "2026-07-01T10:00:00Z", "")
	insertEmail(t, s, d.ID, "canceled", "2026-07-01T10:00:00Z", "connection refused")
	sm, err := s.SummaryStats("2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if sm.Canceled != 1 || sm.Total != 2 {
		t.Errorf("summary = %+v", sm)
	}
	// The operator's own cancel must not read as a delivery failure.
	if sm.SuccessRate != 100 {
		t.Errorf("success rate = %v, want 100 (canceled excluded from the denominator)", sm.SuccessRate)
	}
}

func TestSummaryStatsAllCanceledNoDivideByZero(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("a.test", "mail1", "pk")
	insertEmail(t, s, d.ID, "canceled", "2026-07-01T10:00:00Z", "")
	sm, err := s.SummaryStats("2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if sm.Total != 1 || sm.SuccessRate != 0 {
		t.Errorf("all-canceled summary = %+v", sm)
	}
}

func TestSummaryStatsEmptyNoDivideByZero(t *testing.T) {
	s := testStore(t)
	sm, err := s.SummaryStats("2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if sm.Total != 0 || sm.SuccessRate != 0 {
		t.Errorf("empty summary = %+v", sm)
	}
}

func TestDomainVolume(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("a.test", "mail1", "pk")
	insertEmail(t, s, d.ID, "sent", "2026-07-01T10:00:00Z", "")
	insertEmail(t, s, d.ID, "failed", "2026-07-01T10:00:00Z", "x")
	got, err := s.DomainVolume("2026-07-01T00:00:00Z", "2026-07-02T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].DomainName != "a.test" || got[0].Sent != 1 || got[0].Failed != 1 {
		t.Errorf("domain volume = %+v", got)
	}
}

func TestFailureReasons(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("a.test", "mail1", "pk")
	insertEmail(t, s, d.ID, "failed", "2026-07-01T10:00:00Z", "550 mailbox full")
	insertEmail(t, s, d.ID, "failed", "2026-07-01T11:00:00Z", "550 mailbox full")
	insertEmail(t, s, d.ID, "failed", "2026-07-01T12:00:00Z", "timeout")
	got, err := s.FailureReasons("2026-07-01T00:00:00Z", "2026-07-02T00:00:00Z", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Reason != "550 mailbox full" || got[0].Count != 2 {
		t.Errorf("reasons = %+v", got)
	}
}

func TestMonthlyStatsWrapperEquivalent(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("a.test", "mail1", "pk")
	insertEmail(t, s, d.ID, "sent", "2026-06-15T10:00:00Z", "")
	insertEmail(t, s, d.ID, "failed", "2026-06-16T10:00:00Z", "x")
	insertEmail(t, s, d.ID, "sent", "2026-07-01T10:00:00Z", "") // next month, excluded
	stats, err := s.MonthlyStats("2026-06")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || stats[0].Sent != 1 || stats[0].Failed != 1 {
		t.Errorf("monthly stats = %+v", stats)
	}
}
