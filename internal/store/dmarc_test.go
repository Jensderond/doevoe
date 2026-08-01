package store

import (
	"path/filepath"
	"testing"
)

func dmStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleReport(reportID string) (*DMARCReport, []DMARCRecord) {
	rep := &DMARCReport{
		Org: "google.com", ReportID: reportID, Domain: "client.example",
		RangeBegin: "2026-08-01T00:00:00Z", RangeEnd: "2026-08-02T00:00:00Z",
		ReceivedAt: "2026-08-02T06:00:00Z", Raw: "<feedback/>",
	}
	recs := []DMARCRecord{
		{SourceIP: "203.0.113.7", Count: 11, Disposition: "none", DKIM: "pass", SPF: "pass", HeaderFrom: "client.example"},
		{SourceIP: "198.51.100.9", Count: 3, Disposition: "quarantine", DKIM: "fail", SPF: "fail", HeaderFrom: "client.example"},
	}
	return rep, recs
}

func TestInsertDMARCReportAndDedup(t *testing.T) {
	s := dmStore(t)
	rep, recs := sampleReport("r-1")
	id, dup, err := s.InsertDMARCReport(rep, recs)
	if err != nil || dup || id == 0 {
		t.Fatalf("insert: id=%d dup=%v err=%v", id, dup, err)
	}
	// Same (org, report_id) again: duplicate, no error, no second row.
	rep2, recs2 := sampleReport("r-1")
	_, dup, err = s.InsertDMARCReport(rep2, recs2)
	if err != nil || !dup {
		t.Fatalf("re-insert: dup=%v err=%v, want true nil", dup, err)
	}
	// Different report_id: fresh insert.
	rep3, recs3 := sampleReport("r-2")
	if _, dup, err = s.InsertDMARCReport(rep3, recs3); err != nil || dup {
		t.Fatalf("second report: dup=%v err=%v", dup, err)
	}
	// Verify count is 2 (the dedup'd re-insert must not have bumped it).
	count, err := s.CountDMARCReports()
	if err != nil || count != 2 {
		t.Fatalf("count: %d err=%v, want 2 nil", count, err)
	}
}

func TestPruneDMARCReports(t *testing.T) {
	s := dmStore(t)
	old, oldRecs := sampleReport("r-old")
	old.ReceivedAt = "2026-05-01T00:00:00Z"
	s.InsertDMARCReport(old, oldRecs)
	fresh, freshRecs := sampleReport("r-new")
	s.InsertDMARCReport(fresh, freshRecs)

	n, err := s.PruneDMARCReports("2026-06-01T00:00:00Z")
	if err != nil || n != 1 {
		t.Fatalf("prune: n=%d err=%v, want 1 nil", n, err)
	}
	// Cascade removed the old report's records; the fresh report's remain.
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM dmarc_records`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("records after prune: %d, want 2", count)
	}
}
