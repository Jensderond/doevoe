package store

import (
	"path/filepath"
	"reflect"
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

// seedTwoDomains inserts two reports for two different domains at two
// different received_at times, with a mix of pass/fail records (including
// a dkim=fail/spf=pass record, which must still count as a pass) chosen so
// tests can assert exact per-domain and per-source-ip sums.
//
// Domain a.example (older, received_at 2026-08-01T00:00:00Z):
//
//	1.1.1.1  count=10  dkim=pass spf=fail  -> pass
//	2.2.2.2  count=5   dkim=fail spf=fail  -> fail
//	3.3.3.3  count=2   dkim=fail spf=pass  -> pass (aligned spf pass is enough)
//
// Domain b.example (newer, received_at 2026-08-05T00:00:00Z):
//
//	4.4.4.4  count=7   dkim=pass spf=pass  -> pass
//	1.1.1.1  count=3   dkim=fail spf=fail  -> fail
//	2.2.2.2  count=4   dkim=fail spf=fail  -> fail
//
// So: a.example pass=12 fail=5; b.example pass=7 fail=7.
// Failing-source sums across both reports: 2.2.2.2=9, 1.1.1.1=3 (only its
// failing record counts; its passing record in a.example is excluded).
func seedTwoDomains(t *testing.T, s *Store) {
	t.Helper()
	repA := &DMARCReport{
		Org: "google.com", ReportID: "r-a", Domain: "a.example",
		RangeBegin: "2026-07-31T00:00:00Z", RangeEnd: "2026-08-01T00:00:00Z",
		ReceivedAt: "2026-08-01T00:00:00Z", Raw: "<feedback>a</feedback>",
	}
	recsA := []DMARCRecord{
		{SourceIP: "1.1.1.1", Count: 10, Disposition: "none", DKIM: "pass", SPF: "fail", HeaderFrom: "a.example"},
		{SourceIP: "2.2.2.2", Count: 5, Disposition: "quarantine", DKIM: "fail", SPF: "fail", HeaderFrom: "a.example"},
		{SourceIP: "3.3.3.3", Count: 2, Disposition: "none", DKIM: "fail", SPF: "pass", HeaderFrom: "a.example"},
	}
	if _, dup, err := s.InsertDMARCReport(repA, recsA); err != nil || dup {
		t.Fatalf("seed report a: dup=%v err=%v", dup, err)
	}

	repB := &DMARCReport{
		Org: "google.com", ReportID: "r-b", Domain: "b.example",
		RangeBegin: "2026-08-04T00:00:00Z", RangeEnd: "2026-08-05T00:00:00Z",
		ReceivedAt: "2026-08-05T00:00:00Z", Raw: "<feedback>b</feedback>",
	}
	recsB := []DMARCRecord{
		{SourceIP: "4.4.4.4", Count: 7, Disposition: "none", DKIM: "pass", SPF: "pass", HeaderFrom: "b.example"},
		{SourceIP: "1.1.1.1", Count: 3, Disposition: "quarantine", DKIM: "fail", SPF: "fail", HeaderFrom: "b.example"},
		{SourceIP: "2.2.2.2", Count: 4, Disposition: "quarantine", DKIM: "fail", SPF: "fail", HeaderFrom: "b.example"},
	}
	if _, dup, err := s.InsertDMARCReport(repB, recsB); err != nil || dup {
		t.Fatalf("seed report b: dup=%v err=%v", dup, err)
	}
}

func TestDMARCSummary(t *testing.T) {
	s := dmStore(t)
	seedTwoDomains(t, s)

	t.Run("unbounded window returns both domains with correct sums", func(t *testing.T) {
		got, err := s.DMARCSummary("", "")
		if err != nil {
			t.Fatalf("DMARCSummary: %v", err)
		}
		want := []DMARCDomainSummary{
			{Domain: "a.example", Pass: 12, Fail: 5},
			{Domain: "b.example", Pass: 7, Fail: 7},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("DMARCSummary(\"\",\"\") = %+v, want %+v", got, want)
		}
	})

	t.Run("window excluding the older report returns only the newer domain", func(t *testing.T) {
		got, err := s.DMARCSummary("2026-08-03T00:00:00Z", "")
		if err != nil {
			t.Fatalf("DMARCSummary: %v", err)
		}
		want := []DMARCDomainSummary{
			{Domain: "b.example", Pass: 7, Fail: 7},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("DMARCSummary(windowed) = %+v, want %+v", got, want)
		}
	})

	t.Run("to is exclusive", func(t *testing.T) {
		got, err := s.DMARCSummary("", "2026-08-05T00:00:00Z")
		if err != nil {
			t.Fatalf("DMARCSummary: %v", err)
		}
		want := []DMARCDomainSummary{
			{Domain: "a.example", Pass: 12, Fail: 5},
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("DMARCSummary(to-exclusive) = %+v, want %+v", got, want)
		}
	})
}

func TestDMARCTopFailingSources(t *testing.T) {
	s := dmStore(t)
	seedTwoDomains(t, s)

	got, err := s.DMARCTopFailingSources("", "", 5)
	if err != nil {
		t.Fatalf("DMARCTopFailingSources: %v", err)
	}
	want := []DMARCSource{
		{SourceIP: "2.2.2.2", Count: 9},
		{SourceIP: "1.1.1.1", Count: 3},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DMARCTopFailingSources = %+v, want %+v", got, want)
	}
	for _, r := range got {
		if r.SourceIP == "3.3.3.3" || r.SourceIP == "4.4.4.4" {
			t.Fatalf("source %s passed and must not appear in failing sources", r.SourceIP)
		}
	}

	t.Run("limit caps results", func(t *testing.T) {
		got, err := s.DMARCTopFailingSources("", "", 1)
		if err != nil {
			t.Fatalf("DMARCTopFailingSources: %v", err)
		}
		if len(got) != 1 || got[0].SourceIP != "2.2.2.2" {
			t.Fatalf("DMARCTopFailingSources(limit=1) = %+v, want [{2.2.2.2 9}]", got)
		}
	})
}

func TestListDMARCReports(t *testing.T) {
	s := dmStore(t)
	seedTwoDomains(t, s)

	got, err := s.ListDMARCReports("", "", 10)
	if err != nil {
		t.Fatalf("ListDMARCReports: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListDMARCReports len = %d, want 2", len(got))
	}
	// Newest received_at first: b.example (2026-08-05) before a.example (2026-08-01).
	if got[0].Domain != "b.example" || got[1].Domain != "a.example" {
		t.Fatalf("ListDMARCReports order = [%s, %s], want [b.example, a.example]", got[0].Domain, got[1].Domain)
	}
	if got[0].RecordCount != 3 || got[1].RecordCount != 3 {
		t.Fatalf("RecordCount = [%d, %d], want [3, 3]", got[0].RecordCount, got[1].RecordCount)
	}
	for _, item := range got {
		if item.Raw != "" {
			t.Fatalf("ListDMARCReports must not select raw; got Raw=%q for domain %s", item.Raw, item.Domain)
		}
	}

	t.Run("limit is respected", func(t *testing.T) {
		got, err := s.ListDMARCReports("", "", 1)
		if err != nil {
			t.Fatalf("ListDMARCReports: %v", err)
		}
		if len(got) != 1 || got[0].Domain != "b.example" {
			t.Fatalf("ListDMARCReports(limit=1) = %+v, want [b.example]", got)
		}
	})
}
