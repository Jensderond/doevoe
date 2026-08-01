package store

import "strings"

// DMARCReport is one stored aggregate report. Raw keeps the decompressed
// XML for debugging parser gaps; retention (PruneDMARCReports) bounds it.
type DMARCReport struct {
	ID                                    int64
	Org, ReportID, Domain                 string
	RangeBegin, RangeEnd, ReceivedAt, Raw string
}

// DMARCRecord is one per-source row of a report.
type DMARCRecord struct {
	ID, ReportID                       int64
	SourceIP                           string
	Count                              int64
	Disposition, DKIM, SPF, HeaderFrom string
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

// DMARCDomainSummary is the per-domain rollup for the admin page. Pass/Fail
// are message counts (sums of record counts); a record passes when either
// evaluation passed — DMARC requires one aligned pass, not both.
type DMARCDomainSummary struct {
	Domain     string
	Pass, Fail int64
}

// DMARCSummary rolls up pass/fail message counts per domain, windowed on
// dmarc_reports.received_at (from inclusive, to exclusive; an empty string
// leaves that side unbounded), ordered by domain.
func (s *Store) DMARCSummary(from, to string) ([]DMARCDomainSummary, error) {
	rows, err := s.db.Query(`
		SELECT r.domain,
		       COALESCE(SUM(CASE WHEN rec.dkim='pass' OR rec.spf='pass' THEN rec.count ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN rec.dkim='pass' OR rec.spf='pass' THEN 0 ELSE rec.count END), 0)
		FROM dmarc_reports r JOIN dmarc_records rec ON rec.report_id = r.id
		WHERE (? = '' OR r.received_at >= ?) AND (? = '' OR r.received_at < ?)
		GROUP BY r.domain ORDER BY r.domain`, from, from, to, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DMARCDomainSummary
	for rows.Next() {
		var d DMARCDomainSummary
		if err := rows.Scan(&d.Domain, &d.Pass, &d.Fail); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DMARCSource is a per-source-IP message count for the failing-sources list.
type DMARCSource struct {
	SourceIP string
	Count    int64
}

// DMARCTopFailingSources sums failing message counts by source IP (a record
// fails when neither dkim nor spf passed), windowed like DMARCSummary,
// ordered by count descending and capped at limit.
func (s *Store) DMARCTopFailingSources(from, to string, limit int) ([]DMARCSource, error) {
	rows, err := s.db.Query(`
		SELECT rec.source_ip, SUM(rec.count) AS c
		FROM dmarc_reports r JOIN dmarc_records rec ON rec.report_id = r.id
		WHERE NOT (rec.dkim='pass' OR rec.spf='pass')
		  AND (? = '' OR r.received_at >= ?) AND (? = '' OR r.received_at < ?)
		GROUP BY rec.source_ip ORDER BY c DESC LIMIT ?`, from, from, to, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DMARCSource
	for rows.Next() {
		var d DMARCSource
		if err := rows.Scan(&d.SourceIP, &d.Count); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DMARCReportListItem is a report row plus its record count, for the admin
// list page. Raw is intentionally left empty (see ListDMARCReports).
type DMARCReportListItem struct {
	DMARCReport
	RecordCount int64
}

// ListDMARCReports lists reports newest-received-first, windowed like
// DMARCSummary and capped at limit. It deliberately does not select the
// raw column — list pages don't need megabytes of XML — so Raw is always
// "" on the returned items.
func (s *Store) ListDMARCReports(from, to string, limit int) ([]DMARCReportListItem, error) {
	rows, err := s.db.Query(`
		SELECT r.id, r.org, r.report_id, r.domain, r.range_begin, r.range_end, r.received_at,
		       (SELECT COUNT(*) FROM dmarc_records WHERE report_id = r.id)
		FROM dmarc_reports r
		WHERE (? = '' OR r.received_at >= ?) AND (? = '' OR r.received_at < ?)
		ORDER BY r.received_at DESC, r.id DESC LIMIT ?`, from, from, to, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DMARCReportListItem
	for rows.Next() {
		var item DMARCReportListItem
		if err := rows.Scan(&item.ID, &item.Org, &item.ReportID, &item.Domain,
			&item.RangeBegin, &item.RangeEnd, &item.ReceivedAt, &item.RecordCount); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
