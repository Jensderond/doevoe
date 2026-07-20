package store

type DomainStats struct {
	DomainName   string
	Sent, Failed int
}

func (s *Store) GetState(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM notify_state WHERE key=?`, key).Scan(&v)
	if err != nil {
		return "", nil // unset
	}
	return v, nil
}

func (s *Store) SetState(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO notify_state (key, value) VALUES (?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) AddPendingFailure(emailID int64) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO notify_pending_failures (email_id, created_at) VALUES (?,?)`, emailID, Now())
	return err
}

func (s *Store) ListPendingFailures() ([]*Email, error) {
	rows, err := s.db.Query(`SELECT ` + emailCols + ` FROM emails
		WHERE id IN (SELECT email_id FROM notify_pending_failures) ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Email
	for rows.Next() {
		e, err := scanEmail(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (s *Store) ClearPendingFailures() error {
	_, err := s.db.Exec(`DELETE FROM notify_pending_failures`)
	return err
}

func (s *Store) MonthlyStats(monthPrefix string) ([]DomainStats, error) {
	rows, err := s.db.Query(`SELECT d.name,
		SUM(CASE WHEN e.status='sent' THEN 1 ELSE 0 END),
		SUM(CASE WHEN e.status='failed' THEN 1 ELSE 0 END)
		FROM emails e JOIN domains d ON d.id=e.domain_id
		WHERE e.created_at LIKE ? || '%'
		GROUP BY d.name ORDER BY d.name`, monthPrefix)
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

func (s *Store) FailureRate(domainID int64, since string) (failed, total int, err error) {
	err = s.db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN a.smtp_code>=400 OR a.smtp_code=0 THEN 1 ELSE 0 END), 0),
		COALESCE(COUNT(*), 0)
		FROM delivery_attempts a JOIN emails e ON e.id=a.email_id
		WHERE e.domain_id=? AND a.created_at>=?`, domainID, since).Scan(&failed, &total)
	return
}
