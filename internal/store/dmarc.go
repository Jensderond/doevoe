package store

import "strings"

// DMARCReport is one stored aggregate report. Raw keeps the decompressed
// XML for debugging parser gaps; retention (PruneDMARCReports) bounds it.
type DMARCReport struct {
	ID                                            int64
	Org, ReportID, Domain                         string
	RangeBegin, RangeEnd, ReceivedAt, Raw         string
}

// DMARCRecord is one per-source row of a report.
type DMARCRecord struct {
	ID, ReportID                        int64
	SourceIP                            string
	Count                               int64
	Disposition, DKIM, SPF, HeaderFrom  string
}

// InsertDMARCReport stores a report and its records in one transaction.
// Reporters re-send reports, so (org, report_id) is UNIQUE: a constraint hit
// returns duplicate=true with no error — the caller accepts the message and
// drops it (re-rejecting would just make the reporter retry forever).
func (s *Store) InsertDMARCReport(rep *DMARCReport, recs []DMARCRecord) (int64, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()

	// MaxOpenConns(1): every statement here must use tx, never s.db.
	res, err := tx.Exec(`INSERT INTO dmarc_reports
		(org, report_id, domain, range_begin, range_end, received_at, raw)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rep.Org, rep.ReportID, rep.Domain, rep.RangeBegin, rep.RangeEnd, rep.ReceivedAt, rep.Raw)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, true, nil
		}
		return 0, false, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, false, err
	}
	for _, r := range recs {
		if _, err := tx.Exec(`INSERT INTO dmarc_records
			(report_id, source_ip, count, disposition, dkim, spf, header_from)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, r.SourceIP, r.Count, r.Disposition, r.DKIM, r.SPF, r.HeaderFrom); err != nil {
			return 0, false, err
		}
	}
	return id, false, tx.Commit()
}

// PruneDMARCReports deletes reports received before the given RFC3339 time.
// dmarc_records rows go with them via ON DELETE CASCADE (foreign_keys is on).
func (s *Store) PruneDMARCReports(before string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM dmarc_reports WHERE received_at < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) CountDMARCReports() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM dmarc_reports`).Scan(&n)
	return n, err
}
