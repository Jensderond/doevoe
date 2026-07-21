package store

import (
	"database/sql"
	"errors"
	"strings"
)

type Email struct {
	ID, APIKeyID, DomainID                   int64
	From, To, FromName, ToName               string
	OriginalTo, ReplyTo, Subject             string
	BodyHTML, BodyText, HeadersJSON, Status  string
	Attempts                                 int
	NextAttemptAt, LastError, IdempotencyKey string
	IsSystem                                 bool
	CreatedAt, SentAt                        string
}

const emailCols = `id, COALESCE(api_key_id,0), domain_id, from_addr, to_addr, from_name, to_name, original_to, reply_to, subject,
 body_html, body_text, headers_json, status, attempts, next_attempt_at, last_error,
 COALESCE(idempotency_key,''), is_system, created_at, sent_at`

func scanEmail(row interface{ Scan(...any) error }) (*Email, error) {
	e := &Email{}
	err := row.Scan(&e.ID, &e.APIKeyID, &e.DomainID, &e.From, &e.To, &e.FromName, &e.ToName, &e.OriginalTo, &e.ReplyTo, &e.Subject,
		&e.BodyHTML, &e.BodyText, &e.HeadersJSON, &e.Status, &e.Attempts, &e.NextAttemptAt, &e.LastError,
		&e.IdempotencyKey, &e.IsSystem, &e.CreatedAt, &e.SentAt)
	return e, err
}

func (s *Store) EnqueueEmail(e *Email) (int64, error) {
	if e.NextAttemptAt == "" {
		e.NextAttemptAt = Now()
	}
	if e.CreatedAt == "" {
		e.CreatedAt = Now()
	}
	if e.HeadersJSON == "" {
		e.HeadersJSON = "{}"
	}
	res, err := s.db.Exec(`INSERT INTO emails
		(api_key_id, domain_id, from_addr, to_addr, from_name, to_name, reply_to, subject, body_html, body_text, headers_json,
		 status, next_attempt_at, idempotency_key, is_system, created_at)
		VALUES (NULLIF(?,0),?,?,?,?,?,?,?,?,?,?, 'queued', ?, NULLIF(?,''), ?, ?)`,
		e.APIKeyID, e.DomainID, e.From, e.To, e.FromName, e.ToName, e.ReplyTo, e.Subject, e.BodyHTML, e.BodyText, e.HeadersJSON,
		e.NextAttemptAt, e.IdempotencyKey, e.IsSystem, e.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) GetEmail(id int64) (*Email, error) {
	return scanEmail(s.db.QueryRow(`SELECT `+emailCols+` FROM emails WHERE id=?`, id))
}

func (s *Store) FindByIdempotencyKey(apiKeyID int64, key string) (*Email, error) {
	e, err := scanEmail(s.db.QueryRow(`SELECT `+emailCols+` FROM emails WHERE api_key_id=? AND idempotency_key=?`, apiKeyID, key))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return e, err
}

func (s *Store) ClaimDue(limit int, now string) ([]*Email, error) {
	// next_attempt_at is stamped with the claim time here even though it plays no
	// scheduling role while status='sending' (MarkRetry/MarkSent overwrite it on
	// completion). It exists purely so RequeueStaleSending can tell a row that has
	// been "sending" too long (crash/redeploy mid-send) from one claimed moments ago.
	rows, err := s.db.Query(`UPDATE emails SET status='sending', next_attempt_at=?
		WHERE id IN (SELECT id FROM emails WHERE status='queued' AND next_attempt_at<=? ORDER BY next_attempt_at LIMIT ?)
		RETURNING `+emailCols, now, now, limit)
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

// RequeueStaleSending resets emails stuck in 'sending' (e.g. because the process
// crashed mid-send) back to 'queued' so they get picked up again. A row is
// considered stale when its next_attempt_at (stamped at claim time by ClaimDue)
// is older than the given cutoff. Callers pass cutoff = now - staleness window;
// the store itself does no time math.
func (s *Store) RequeueStaleSending(olderThan string) (int64, error) {
	res, err := s.db.Exec(`UPDATE emails SET status='queued' WHERE status='sending' AND next_attempt_at<=?`, olderThan)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) MarkSent(id int64, at string) error {
	_, err := s.db.Exec(`UPDATE emails SET status='sent', attempts=attempts+1, sent_at=?, last_error='' WHERE id=?`, at, id)
	return err
}

func (s *Store) MarkRetry(id int64, nextAt, errMsg string) error {
	_, err := s.db.Exec(`UPDATE emails SET status='queued', attempts=attempts+1, next_attempt_at=?, last_error=? WHERE id=?`,
		nextAt, errMsg, id)
	return err
}

func (s *Store) MarkFailed(id int64, errMsg string) error {
	_, err := s.db.Exec(`UPDATE emails SET status='failed', attempts=attempts+1, last_error=? WHERE id=?`, errMsg, id)
	return err
}

func (s *Store) RequeueEmail(id int64, newTo string) error {
	if newTo != "" {
		_, err := s.db.Exec(`UPDATE emails SET
			original_to = CASE WHEN original_to='' THEN to_addr ELSE original_to END,
			to_addr=?, status='queued', attempts=0, next_attempt_at=?, last_error='' WHERE id=?`,
			newTo, Now(), id)
		return err
	}
	_, err := s.db.Exec(`UPDATE emails SET status='queued', attempts=0, next_attempt_at=?, last_error='' WHERE id=?`, Now(), id)
	return err
}

type EmailFilter struct {
	Status   string
	DomainID int64
	Search   string
	// CreatedFrom/CreatedTo bound created_at as RFC3339 timestamps:
	// from is inclusive, to is exclusive (pass the day after for a
	// human-inclusive "to" date). Empty means unbounded.
	CreatedFrom string
	CreatedTo   string
	Limit       int
	Offset      int
}

func (s *Store) ListEmails(f EmailFilter) ([]*Email, error) {
	if f.Limit == 0 {
		f.Limit = 50
	}
	var where []string
	var args []any
	if f.Status != "" {
		where = append(where, "status=?")
		args = append(args, f.Status)
	}
	if f.DomainID != 0 {
		where = append(where, "domain_id=?")
		args = append(args, f.DomainID)
	}
	if f.Search != "" {
		where = append(where, "(to_addr LIKE ? OR subject LIKE ?)")
		args = append(args, "%"+f.Search+"%", "%"+f.Search+"%")
	}
	if f.CreatedFrom != "" {
		where = append(where, "created_at>=?")
		args = append(args, f.CreatedFrom)
	}
	if f.CreatedTo != "" {
		where = append(where, "created_at<?")
		args = append(args, f.CreatedTo)
	}
	q := `SELECT ` + emailCols + ` FROM emails`
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
	args = append(args, f.Limit, f.Offset)
	rows, err := s.db.Query(q, args...)
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
