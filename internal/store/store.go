package store

import (
	"database/sql"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

const schema = `
CREATE TABLE IF NOT EXISTS domains (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  dkim_selector TEXT NOT NULL,
  dkim_private_key TEXT NOT NULL,
  spf_verified INTEGER NOT NULL DEFAULT 0,
  dkim_verified INTEGER NOT NULL DEFAULT 0,
  dmarc_verified INTEGER NOT NULL DEFAULT 0,
  last_checked_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  domain_id INTEGER NOT NULL REFERENCES domains(id),
  revoked INTEGER NOT NULL DEFAULT 0,
  last_used_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS emails (
  id INTEGER PRIMARY KEY,
  api_key_id INTEGER REFERENCES api_keys(id),
  domain_id INTEGER NOT NULL REFERENCES domains(id),
  from_addr TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  from_name TEXT NOT NULL DEFAULT '',
  to_name TEXT NOT NULL DEFAULT '',
  original_to TEXT NOT NULL DEFAULT '',
  reply_to TEXT NOT NULL DEFAULT '',
  subject TEXT NOT NULL,
  body_html TEXT NOT NULL DEFAULT '',
  body_text TEXT NOT NULL DEFAULT '',
  headers_json TEXT NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  last_error TEXT NOT NULL DEFAULT '',
  idempotency_key TEXT,
  is_system INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  sent_at TEXT NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_emails_idem
  ON emails(api_key_id, idempotency_key) WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_emails_status_next ON emails(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_emails_domain_created ON emails(domain_id, created_at);
CREATE INDEX IF NOT EXISTS idx_emails_to ON emails(to_addr);
CREATE TABLE IF NOT EXISTS delivery_attempts (
  id INTEGER PRIMARY KEY,
  email_id INTEGER NOT NULL REFERENCES emails(id),
  attempt_no INTEGER NOT NULL,
  mx_host TEXT NOT NULL DEFAULT '',
  smtp_code INTEGER NOT NULL DEFAULT 0,
  response TEXT NOT NULL DEFAULT '',
  duration_ms INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attempts_email ON delivery_attempts(email_id);
CREATE TABLE IF NOT EXISTS webhooks (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  events TEXT NOT NULL DEFAULT '',
  active INTEGER NOT NULL DEFAULT 1,
  last_status INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  last_delivery_at TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id INTEGER PRIMARY KEY,
  webhook_id INTEGER NOT NULL REFERENCES webhooks(id),
  -- No FK on email_id: events that aren't about a specific email store 0,
  -- which no emails row will ever have.
  email_id INTEGER NOT NULL DEFAULT 0,
  event TEXT NOT NULL,
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  response_code INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  delivered_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status_next
  ON webhook_deliveries(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_hook ON webhook_deliveries(webhook_id, id);
CREATE TABLE IF NOT EXISTS notify_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notify_pending_failures (
  email_id INTEGER PRIMARY KEY REFERENCES emails(id),
  created_at TEXT NOT NULL
);
`

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // SQLite single-writer; avoids SQLITE_BUSY entirely
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// migrate applies additive, idempotent schema changes for DBs created before a
// column existed. CREATE TABLE IF NOT EXISTS (in schema, above) never adds
// columns to an already-existing table, so each additive column needs an ALTER
// here. On a fresh DB the column already exists (from the schema constant), so
// the ALTER returns "duplicate column name" — that specific error is expected
// and ignored. Any other error is fatal. This is the migration pattern for the
// project: append additive ALTERs; never rewrite or reorder existing ones.
func migrate(db *sql.DB) error {
	stmts := []string{
		`ALTER TABLE emails ADD COLUMN from_name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE emails ADD COLUMN to_name TEXT NOT NULL DEFAULT ''`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
			return err
		}
	}
	return nil
}

func Now() string { return time.Now().UTC().Format(time.RFC3339) }

func FmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func ParseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}
