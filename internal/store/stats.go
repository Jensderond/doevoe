package store

import "time"

type DayCount struct {
	Date         string // YYYY-MM-DD (UTC)
	Sent, Failed int
}

type Summary struct {
	Sent, Failed, Queued, Total int
	SuccessRate                 float64 // 0..100; 0 when Total == 0
}

// DailyVolume returns per-day sent/failed counts for emails created in the
// half-open range [from, to). Days with no emails are omitted (the caller
// fills gaps for a continuous axis).
func (s *Store) DailyVolume(from, to string) ([]DayCount, error) {
	rows, err := s.db.Query(`SELECT substr(created_at,1,10) AS day,
		SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END),
		SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)
		FROM emails
		WHERE created_at >= ? AND created_at < ?
		GROUP BY day ORDER BY day`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DayCount
	for rows.Next() {
		var d DayCount
		if err := rows.Scan(&d.Date, &d.Sent, &d.Failed); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SummaryStats returns headline totals for emails created in [from, to).
func (s *Store) SummaryStats(from, to string) (Summary, error) {
	var sm Summary
	// COALESCE guards the all-NULL row SQLite returns when nothing matches.
	err := s.db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status IN ('queued','sending') THEN 1 ELSE 0 END), 0),
		COUNT(*)
		FROM emails WHERE created_at >= ? AND created_at < ?`, from, to).
		Scan(&sm.Sent, &sm.Failed, &sm.Queued, &sm.Total)
	if err != nil {
		return Summary{}, err
	}
	if sm.Total > 0 {
		sm.SuccessRate = float64(sm.Sent) / float64(sm.Total) * 100
	}
	return sm, nil
}

// DomainVolume returns per-domain sent/failed counts for [from, to).
func (s *Store) DomainVolume(from, to string) ([]DomainStats, error) {
	rows, err := s.db.Query(`SELECT d.name,
		SUM(CASE WHEN e.status='sent' THEN 1 ELSE 0 END),
		SUM(CASE WHEN e.status='failed' THEN 1 ELSE 0 END)
		FROM emails e JOIN domains d ON d.id=e.domain_id
		WHERE e.created_at >= ? AND e.created_at < ?
		GROUP BY d.name ORDER BY d.name`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainStats
	for rows.Next() {
		var st DomainStats
		if err := rows.Scan(&st.DomainName, &st.Sent, &st.Failed); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// FailureReasons returns the most common last_error values among failed emails
// created in [from, to), most frequent first.
func (s *Store) FailureReasons(from, to string, limit int) ([]ReasonCount, error) {
	rows, err := s.db.Query(`SELECT last_error, COUNT(*) FROM emails
		WHERE status='failed' AND created_at >= ? AND created_at < ? AND last_error != ''
		GROUP BY last_error ORDER BY COUNT(*) DESC LIMIT ?`, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReasonCount
	for rows.Next() {
		var rc ReasonCount
		if err := rows.Scan(&rc.Reason, &rc.Count); err != nil {
			return nil, err
		}
		out = append(out, rc)
	}
	return out, rows.Err()
}

// monthRange converts a "2006-01" month prefix to the half-open UTC range
// [firstOfMonth, firstOfNextMonth). Because store timestamps are fixed-width
// RFC3339 UTC strings, this range is lexicographically equivalent to the old
// `created_at LIKE 'YYYY-MM%'` filter.
func monthRange(monthPrefix string) (from, to string) {
	t, err := time.Parse("2006-01", monthPrefix)
	if err != nil {
		// Defensive: a malformed prefix scopes to its literal string range.
		return monthPrefix, monthPrefix + "￿"
	}
	return FmtTime(t), FmtTime(t.AddDate(0, 1, 0))
}
