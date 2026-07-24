package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
)

// Webhook is an admin-configured HTTP endpoint that doevoe POSTs event
// payloads to. Secret is stored in the clear, unlike api_keys which store
// only a hash: it is not a bearer credential we authenticate against, it is
// the HMAC key every delivery attempt has to re-derive a signature from, and
// the receiver needs the identical value to verify it.
type Webhook struct {
	ID                int64
	Name, URL, Secret string
	Events            []string
	Active            bool
	// LastStatus/LastError/LastDeliveryAt summarise the most recent attempt
	// against this endpoint so the admin list can show health without joining
	// the deliveries table.
	LastStatus     int
	LastError      string
	LastDeliveryAt string
	CreatedAt      string
}

// Subscribed reports whether this webhook wants the given event name.
func (w *Webhook) Subscribed(event string) bool {
	for _, e := range w.Events {
		if e == event {
			return true
		}
	}
	return false
}

// WebhookDelivery is one queued attempt-set at delivering one event to one
// webhook. Payload is snapshotted at enqueue time so a retry replays the
// state as of the event, not as of the retry.
type WebhookDelivery struct {
	ID, WebhookID int64
	// EmailID is 0 for events that aren't about a specific email.
	EmailID                int64
	Event, Payload, Status string
	Attempts               int
	NextAttemptAt          string
	ResponseCode           int
	LastError              string
	CreatedAt, DeliveredAt string
}

const webhookCols = `id, name, url, secret, events, active, last_status, last_error, last_delivery_at, created_at`

func scanWebhook(row interface{ Scan(...any) error }) (*Webhook, error) {
	w := &Webhook{}
	var events string
	err := row.Scan(&w.ID, &w.Name, &w.URL, &w.Secret, &events, &w.Active,
		&w.LastStatus, &w.LastError, &w.LastDeliveryAt, &w.CreatedAt)
	w.Events = splitEvents(events)
	return w, err
}

// splitEvents parses the comma-separated events column, dropping empties so a
// webhook with no events reads back as a nil slice rather than [""].
func splitEvents(s string) []string {
	var out []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

func (s *Store) CreateWebhook(name, url, secret string, events []string) (*Webhook, error) {
	res, err := s.db.Exec(`INSERT INTO webhooks (name, url, secret, events, created_at) VALUES (?,?,?,?,?)`,
		name, url, secret, strings.Join(events, ","), Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.GetWebhook(id)
}

func (s *Store) GetWebhook(id int64) (*Webhook, error) {
	return scanWebhook(s.db.QueryRow(`SELECT `+webhookCols+` FROM webhooks WHERE id=?`, id))
}

func (s *Store) ListWebhooks() ([]*Webhook, error) {
	return s.queryWebhooks(`SELECT ` + webhookCols + ` FROM webhooks ORDER BY created_at DESC, id DESC`)
}

// ListActiveWebhooksForEvent returns the active webhooks subscribed to event.
// The subscription filter is applied in Go rather than SQL: the events column
// is a comma-separated list, so a LIKE would match prefixes of other event
// names ("email.sent" inside "email.sent_test") — exact membership is what we
// want here.
func (s *Store) ListActiveWebhooksForEvent(event string) ([]*Webhook, error) {
	all, err := s.queryWebhooks(`SELECT ` + webhookCols + ` FROM webhooks WHERE active=1 ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var out []*Webhook
	for _, w := range all {
		if w.Subscribed(event) {
			out = append(out, w)
		}
	}
	return out, nil
}

func (s *Store) queryWebhooks(q string, args ...any) ([]*Webhook, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Webhook
	for rows.Next() {
		w, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (s *Store) UpdateWebhook(id int64, name, url string, events []string, active bool) error {
	_, err := s.db.Exec(`UPDATE webhooks SET name=?, url=?, events=?, active=? WHERE id=?`,
		name, url, strings.Join(events, ","), active, id)
	return err
}

// TouchWebhook records the outcome of the most recent delivery attempt
// against the endpoint itself (see Webhook.LastStatus).
func (s *Store) TouchWebhook(id int64, code int, errMsg, at string) error {
	_, err := s.db.Exec(`UPDATE webhooks SET last_status=?, last_error=?, last_delivery_at=? WHERE id=?`,
		code, errMsg, at, id)
	return err
}

// DeleteWebhook removes the endpoint and its delivery history. Both go in one
// transaction because webhook_deliveries has a foreign key onto webhooks and
// foreign_keys is on: deleting the parent first would fail, and deleting the
// children without committing the parent delete would silently drop history
// while keeping the endpoint.
func (s *Store) DeleteWebhook(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM webhook_deliveries WHERE webhook_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM webhooks WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

const deliveryCols = `id, webhook_id, email_id, event, payload, status, attempts, next_attempt_at,
 response_code, last_error, created_at, delivered_at`

func scanDelivery(row interface{ Scan(...any) error }) (*WebhookDelivery, error) {
	d := &WebhookDelivery{}
	err := row.Scan(&d.ID, &d.WebhookID, &d.EmailID, &d.Event, &d.Payload, &d.Status, &d.Attempts,
		&d.NextAttemptAt, &d.ResponseCode, &d.LastError, &d.CreatedAt, &d.DeliveredAt)
	return d, err
}

func (s *Store) EnqueueWebhookDelivery(d *WebhookDelivery) (int64, error) {
	if d.NextAttemptAt == "" {
		d.NextAttemptAt = Now()
	}
	if d.CreatedAt == "" {
		d.CreatedAt = Now()
	}
	res, err := s.db.Exec(`INSERT INTO webhook_deliveries
		(webhook_id, email_id, event, payload, status, next_attempt_at, created_at)
		VALUES (?,?,?,?,'queued',?,?)`,
		d.WebhookID, d.EmailID, d.Event, d.Payload, d.NextAttemptAt, d.CreatedAt)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) GetWebhookDelivery(id int64) (*WebhookDelivery, error) {
	return scanDelivery(s.db.QueryRow(`SELECT ` + deliveryCols + ` FROM webhook_deliveries WHERE id=?`, id))
}

// ClaimDueWebhookDeliveries flips due deliveries to 'sending' and returns
// them, exactly like ClaimDue does for emails: next_attempt_at is stamped
// with the claim time so RequeueStaleWebhookDeliveries can tell a row that
// has been sending too long (crash mid-POST) from one claimed moments ago.
func (s *Store) ClaimDueWebhookDeliveries(limit int, now string) ([]*WebhookDelivery, error) {
	rows, err := s.db.Query(`UPDATE webhook_deliveries SET status='sending', next_attempt_at=?
		WHERE id IN (SELECT id FROM webhook_deliveries WHERE status='queued' AND next_attempt_at<=?
		             ORDER BY next_attempt_at LIMIT ?)
		RETURNING `+deliveryCols, now, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WebhookDelivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) RequeueStaleWebhookDeliveries(olderThan string) (int64, error) {
	res, err := s.db.Exec(`UPDATE webhook_deliveries SET status='queued'
		WHERE status='sending' AND next_attempt_at<=?`, olderThan)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) MarkWebhookDelivered(id int64, code int, at string) error {
	_, err := s.db.Exec(`UPDATE webhook_deliveries SET status='delivered', attempts=attempts+1,
		response_code=?, last_error='', delivered_at=? WHERE id=?`, code, at, id)
	return err
}

func (s *Store) MarkWebhookDeliveryRetry(id int64, nextAt string, code int, errMsg string) error {
	_, err := s.db.Exec(`UPDATE webhook_deliveries SET status='queued', attempts=attempts+1,
		next_attempt_at=?, response_code=?, last_error=? WHERE id=?`, nextAt, code, errMsg, id)
	return err
}

func (s *Store) MarkWebhookDeliveryFailed(id int64, code int, errMsg string) error {
	_, err := s.db.Exec(`UPDATE webhook_deliveries SET status='failed', attempts=attempts+1,
		response_code=?, last_error=? WHERE id=?`, code, errMsg, id)
	return err
}

func (s *Store) ListWebhookDeliveries(webhookID int64, limit int) ([]*WebhookDelivery, error) {
	if limit == 0 {
		limit = 25
	}
	rows, err := s.db.Query(`SELECT `+deliveryCols+` FROM webhook_deliveries
		WHERE webhook_id=? ORDER BY id DESC LIMIT ?`, webhookID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*WebhookDelivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PruneWebhookDeliveries drops finished delivery rows created before the
// given timestamp. Deliveries are pure history (the email row is the record
// of what happened), and one email event fans out to every subscribed
// endpoint, so without pruning this table grows faster than emails does.
// In-flight rows ('queued'/'sending') are never pruned.
func (s *Store) PruneWebhookDeliveries(before string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM webhook_deliveries
		WHERE created_at<? AND status IN ('delivered','failed')`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GenerateWebhookSecret returns the HMAC signing secret handed to the
// receiver. The whsec_ prefix makes it recognisable in the receiver's own
// config/logs, mirroring the dv_ prefix on API keys.
func GenerateWebhookSecret() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "whsec_" + hex.EncodeToString(buf), nil
}

// IsNotFound reports whether err means the queried row simply doesn't exist,
// so callers can tell "the endpoint was deleted mid-flight" from a real query
// failure without importing database/sql themselves.
func IsNotFound(err error) bool { return errors.Is(err, sql.ErrNoRows) }
