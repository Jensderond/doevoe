package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "doevoe.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenMigrates(t *testing.T) {
	s := testStore(t)
	for _, table := range []string{"domains", "api_keys", "emails", "delivery_attempts", "notify_state", "notify_pending_failures"} {
		var n int
		err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n)
		if err != nil || n != 1 {
			t.Errorf("table %s missing (err=%v)", table, err)
		}
	}
}

func TestMigrateAddsDisplayNameColumnsIdempotently(t *testing.T) {
	// modernc.org/sqlite is registered globally by store.go's blank import.
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "old.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Simulate a pre-display-name DB: an emails table WITHOUT from_name/to_name.
	if _, err := db.Exec(`CREATE TABLE emails (id INTEGER PRIMARY KEY, from_addr TEXT NOT NULL DEFAULT '')`); err != nil {
		t.Fatal(err)
	}
	// First run adds the columns; second must tolerate "duplicate column name".
	for i := 1; i <= 2; i++ {
		if err := migrate(db); err != nil {
			t.Fatalf("migrate run %d: %v", i, err)
		}
	}
	for _, col := range []string{"from_name", "to_name"} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM pragma_table_info('emails') WHERE name=?`, col).Scan(&n); err != nil || n != 1 {
			t.Fatalf("column %s missing after migrate (n=%d err=%v)", col, n, err)
		}
	}
}
