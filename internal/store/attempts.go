package store

type Attempt struct {
	ID, EmailID         int64
	AttemptNo, SMTPCode int
	MXHost, Response    string
	DurationMs          int64
	CreatedAt           string
}

func (s *Store) RecordAttempt(emailID int64, attemptNo, code int, mxHost, response string, durationMs int64) error {
	_, err := s.db.Exec(`INSERT INTO delivery_attempts (email_id, attempt_no, smtp_code, mx_host, response, duration_ms, created_at)
		VALUES (?,?,?,?,?,?,?)`, emailID, attemptNo, code, mxHost, response, durationMs, Now())
	return err
}

func (s *Store) ListAttempts(emailID int64) ([]*Attempt, error) {
	rows, err := s.db.Query(`SELECT id, email_id, attempt_no, smtp_code, mx_host, response, duration_ms, created_at
		FROM delivery_attempts WHERE email_id=? ORDER BY id`, emailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Attempt
	for rows.Next() {
		a := &Attempt{}
		if err := rows.Scan(&a.ID, &a.EmailID, &a.AttemptNo, &a.SMTPCode, &a.MXHost, &a.Response, &a.DurationMs, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
