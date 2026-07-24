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
	for _, table := range []string{"domains", "api_keys", "emails", "delivery_attempts", "notify_state",
		"notify_pending_failures", "webhooks", "webhook_deliveries"} {
		var n int
		err := s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n)
		if err != nil || n != 1 {
			t.Errorf("table %s missing (err=%v)", table, err)
		}
	}
}

func TestMigrateAddsColumnsIdempotently(t *testing.T) {
	// modernc.org/sqlite is registered globally by store.go's blank import.
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "old.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Simulate a DB from before each additive column: an emails table WITHOUT
	// from_name/to_name, and a webhooks table WITHOUT domain_id.
	for _, stmt := range []string{
		`CREATE TABLE emails (id INTEGER PRIMARY KEY, from_addr TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE webhooks (id INTEGER PRIMARY KEY, url TEXT NOT NULL DEFAULT '')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	// First run adds the columns; second must tolerate "duplicate column name".
	for i := 1; i <= 2; i++ {
		if err := migrate(db); err != nil {
			t.Fatalf("migrate run %d: %v", i, err)
		}
	}
	for table, cols := range map[string][]string{
		"emails":   {"from_name", "to_name"},
		"webhooks": {"domain_id"},
	} {
		for _, col := range cols {
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM pragma_table_info(?) WHERE name=?`, table, col).Scan(&n); err != nil || n != 1 {
				t.Fatalf("column %s.%s missing after migrate (n=%d err=%v)", table, col, n, err)
			}
		}
	}
}

// An endpoint that predates per-domain scoping must keep its "all domains"
// behaviour: the migration's default has to read back as DomainID 0.
func TestMigratedWebhookDefaultsToAllDomains(t *testing.T) {
	s := testStore(t)
	if _, err := s.db.Exec(`INSERT INTO webhooks (name, url, secret, events, created_at)
		VALUES ('legacy', 'https://recv.test/h', 'sec', 'email.sent', ?)`, Now()); err != nil {
		t.Fatal(err)
	}
	hooks, err := s.ListWebhooks()
	if err != nil || len(hooks) != 1 {
		t.Fatalf("hooks = %+v, %v", hooks, err)
	}
	if !hooks[0].AllDomains() {
		t.Fatalf("legacy webhook = %+v, want DomainID 0", hooks[0])
	}
}
