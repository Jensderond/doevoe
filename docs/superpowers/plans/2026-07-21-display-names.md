# Display Names on From/To Headers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve sender/recipient display names on outgoing `From` and `To` headers while keeping bare addresses for all routing.

**Architecture:** Store the display name in new `from_name`/`to_name` columns alongside the bare address. Compose the RFC 5322 header at build time via `net/mail`; every routing consumer (SMTP envelope, MX lookup, from-domain match, DKIM signing) keeps using the bare `From`/`To` unchanged. A first-of-its-kind idempotent migration adds the columns to existing DBs.

**Tech Stack:** Go, `net/mail` (`Address.String()` for RFC 2047 encoding + injection-safe formatting), embedded SQLite (`modernc.org/sqlite`), `github.com/emersion/go-msgauth/dkim`.

## Global Constraints

- Timestamps stored as RFC3339 strings via `store.Now()` / `store.FmtTime()`; no SQLite native time.
- `db.SetMaxOpenConns(1)` is deliberate (SQLite single-writer) — do not change.
- `from_addr` / `to_addr` are the **bare** routing addresses (envelope `MAIL FROM`/`RCPT TO`, MX lookup `e.To[LastIndex("@")+1:]`, from-domain match). Never put a display name in them.
- Header injection defense: reject/neutralize raw CR/LF in any header value. `mail.Address.String()` RFC 2047-encodes control chars, so it never emits raw CR/LF.
- Validate at ingress (`internal/api`) AND at build (`internal/delivery`) — the codebase deliberately double-validates; keep both.
- `go vet ./...` and `go test ./...` must pass (matches CI).

---

### Task 1: Store — columns, struct field, scan/insert, migration

**Files:**
- Modify: `internal/store/store.go` (schema constant, `Open`, add `migrate`, add `strings` import)
- Modify: `internal/store/emails.go` (`Email` struct, `emailCols`, `scanEmail`, `EnqueueEmail`)
- Test: `internal/store/emails_test.go` (round-trip), `internal/store/store_test.go` (migration idempotency)

**Interfaces:**
- Produces: `store.Email` gains `FromName string`, `ToName string`. `EnqueueEmail` persists them; `GetEmail`/`scanEmail` populate them. `store.Open` remains `func(path string) (*Store, error)`.

- [ ] **Step 1: Write the failing round-trip test**

Add to `internal/store/emails_test.go`:

```go
func TestDisplayNameRoundTrip(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, err := s.EnqueueEmail(&Email{DomainID: d.ID, From: "a@example.com", To: "b@dest.test",
		FromName: "Atelier Cornelia", ToName: "Jens de Rond", Subject: "hi", BodyText: "yo"})
	if err != nil {
		t.Fatal(err)
	}
	e, err := s.GetEmail(id)
	if err != nil {
		t.Fatal(err)
	}
	if e.FromName != "Atelier Cornelia" || e.ToName != "Jens de Rond" {
		t.Fatalf("names not round-tripped: from=%q to=%q", e.FromName, e.ToName)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/ -run TestDisplayNameRoundTrip`
Expected: FAIL — compile error, `store.Email` has no field `FromName`.

- [ ] **Step 3: Add struct fields, columns, scan, insert**

In `internal/store/emails.go`, change the `Email` struct's second line to add the two fields:

```go
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
```

Update `emailCols` to include the two columns right after `to_addr`:

```go
const emailCols = `id, COALESCE(api_key_id,0), domain_id, from_addr, to_addr, from_name, to_name, original_to, reply_to, subject,
 body_html, body_text, headers_json, status, attempts, next_attempt_at, last_error,
 COALESCE(idempotency_key,''), is_system, created_at, sent_at`
```

Update `scanEmail` to scan them in the same position (after `&e.To`):

```go
func scanEmail(row interface{ Scan(...any) error }) (*Email, error) {
	e := &Email{}
	err := row.Scan(&e.ID, &e.APIKeyID, &e.DomainID, &e.From, &e.To, &e.FromName, &e.ToName, &e.OriginalTo, &e.ReplyTo, &e.Subject,
		&e.BodyHTML, &e.BodyText, &e.HeadersJSON, &e.Status, &e.Attempts, &e.NextAttemptAt, &e.LastError,
		&e.IdempotencyKey, &e.IsSystem, &e.CreatedAt, &e.SentAt)
	return e, err
}
```

Update `EnqueueEmail`'s INSERT to write them:

```go
	res, err := s.db.Exec(`INSERT INTO emails
		(api_key_id, domain_id, from_addr, to_addr, from_name, to_name, reply_to, subject, body_html, body_text, headers_json,
		 status, next_attempt_at, idempotency_key, is_system, created_at)
		VALUES (NULLIF(?,0),?,?,?,?,?,?,?,?,?,?, 'queued', ?, NULLIF(?,''), ?, ?)`,
		e.APIKeyID, e.DomainID, e.From, e.To, e.FromName, e.ToName, e.ReplyTo, e.Subject, e.BodyHTML, e.BodyText, e.HeadersJSON,
		e.NextAttemptAt, e.IdempotencyKey, e.IsSystem, e.CreatedAt)
```

In `internal/store/store.go`, add the two columns to the `emails` table in the `schema` constant, right after the `to_addr` line:

```go
  from_addr TEXT NOT NULL,
  to_addr TEXT NOT NULL,
  from_name TEXT NOT NULL DEFAULT '',
  to_name TEXT NOT NULL DEFAULT '',
  original_to TEXT NOT NULL DEFAULT '',
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/store/ -run TestDisplayNameRoundTrip`
Expected: PASS (fresh DB gets the columns from the schema constant).

- [ ] **Step 5: Write the failing migration test**

This must exercise the *column-less* path (a fresh `Open` gets the columns from the schema constant, so it would not test the migration). Build a bare `emails` table without the new columns, then run `migrate` twice to prove it both adds the columns and tolerates re-runs.

Add `"database/sql"` to the imports in `internal/store/store_test.go` (it already imports `path/filepath` and `testing`), then add:

```go
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
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/store/ -run TestMigrateAddsDisplayNameColumnsIdempotently`
Expected: FAIL — compile error, `migrate` is undefined.

- [ ] **Step 7: Add the migrate() step**

In `internal/store/store.go`, add `"strings"` to the import block, add a `migrate` call in `Open` after the schema exec, and define `migrate`:

```go
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
```

- [ ] **Step 8: Run the store tests and vet**

Run: `go test ./internal/store/ && go vet ./internal/store/`
Expected: PASS, no vet complaints. (`TestOpenMigrates` and all existing store tests still pass.)

- [ ] **Step 9: Commit**

```bash
git add internal/store/store.go internal/store/emails.go internal/store/emails_test.go internal/store/store_test.go
git commit -m "feat(store): add from_name/to_name columns with idempotent migration"
```

---

### Task 2: Delivery — FormatAddress + composed From/To headers

**Files:**
- Modify: `internal/delivery/message.go` (add `net/mail` import, add `FormatAddress`, compose+validate `From`/`To` in `BuildMessage`)
- Test: `internal/delivery/message_test.go`

**Interfaces:**
- Consumes: `store.Email.FromName` / `store.Email.ToName` (Task 1).
- Produces: `delivery.FormatAddress(name, addr string) string` — returns `(&mail.Address{Name: name, Address: addr}).String()` when `name != ""`, else the bare `addr`. Used by `internal/api` (Task 3).

- [ ] **Step 1: Write the failing tests**

Add to `internal/delivery/message_test.go`:

```go
func TestBuildMessageDisplayName(t *testing.T) {
	e := &store.Email{From: "website@ateliercornelia.nl", FromName: "Atelier Cornelia",
		To: "jens@dest.test", ToName: "Jens de Rond", Subject: "Hi", BodyText: "yo", HeadersJSON: "{}"}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Atelier Cornelia", "<website@ateliercornelia.nl>", "Jens de Rond", "<jens@dest.test>"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q\n%s", want, msg)
		}
	}
}

func TestBuildMessageEncodesNonASCIIName(t *testing.T) {
	e := &store.Email{From: "a@example.com", FromName: "Café Cornelia",
		To: "b@dest.test", Subject: "Hi", BodyText: "yo", HeadersJSON: "{}"}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg, "Café") {
		t.Error("non-ASCII name must be RFC 2047-encoded, found raw UTF-8")
	}
	if !strings.Contains(msg, "=?utf-8?") {
		t.Errorf("expected RFC 2047 encoded-word in From header\n%s", msg)
	}
}

func TestBuildMessageNeutralizesCRLFInName(t *testing.T) {
	e := &store.Email{From: "a@example.com", FromName: "Evil\r\nBcc: x@y.com",
		To: "b@dest.test", Subject: "Hi", BodyText: "yo", HeadersJSON: "{}"}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		return // rejecting the injection is an acceptable outcome
	}
	if strings.Contains(msg, "\r\nBcc: x@y.com") {
		t.Error("CRLF in display name leaked an injected header")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/delivery/ -run 'TestBuildMessageDisplayName|TestBuildMessageEncodesNonASCIIName|TestBuildMessageNeutralizesCRLFInName'`
Expected: FAIL — `TestBuildMessageDisplayName` misses `<website@ateliercornelia.nl>` (currently written bare, no angle brackets) and `TestBuildMessageEncodesNonASCIIName` misses the encoded-word.

- [ ] **Step 3: Add FormatAddress and use it in BuildMessage**

In `internal/delivery/message.go`, add `"net/mail"` to the import block.

Add the helper (near `crlf`/`randHex`):

```go
// FormatAddress renders an address for a From/To header. With a display name it
// returns the RFC 5322 "Name <addr>" form via net/mail, which RFC 2047-encodes
// non-ASCII names, quotes specials, and never emits raw CR/LF (so it is
// injection-safe by construction). With an empty name it returns the bare
// address unchanged, preserving the pre-display-name behavior.
func FormatAddress(name, addr string) string {
	if name == "" {
		return addr
	}
	return (&mail.Address{Name: name, Address: addr}).String()
}
```

In `BuildMessage`, replace the top-of-function `From`/`To` validation:

```go
	fromHdr := FormatAddress(e.FromName, e.From)
	toHdr := FormatAddress(e.ToName, e.To)
	if err := validateHeaderValue("From", fromHdr); err != nil {
		return "", err
	}
	if err := validateHeaderValue("To", toHdr); err != nil {
		return "", err
	}
```

(That replaces the two existing `validateHeaderValue("From", e.From)` / `("To", e.To)` blocks.)

Then replace the two write calls:

```go
	write("From", fromHdr)
	write("To", toHdr)
```

- [ ] **Step 4: Run the delivery tests to verify they pass**

Run: `go test ./internal/delivery/`
Expected: PASS — the three new tests plus all existing ones (`TestBuildMessageMultipart` etc., whose bare `From: a@example.com\r\n` assertions still hold since those emails have empty names).

- [ ] **Step 5: Commit**

```bash
git add internal/delivery/message.go internal/delivery/message_test.go
git commit -m "feat(delivery): render display names on From/To via net/mail"
```

---

### Task 3: API — capture and validate display names at ingress

**Files:**
- Modify: `internal/api/api.go` (`postEmail`: ingress validation + pass `FromName`/`ToName`)
- Test: `internal/api/api_test.go`

**Interfaces:**
- Consumes: `delivery.FormatAddress` (Task 2), `store.Email.FromName`/`ToName` (Task 1).

- [ ] **Step 1: Write the failing test**

Add to `internal/api/api_test.go` (`encoding/json` and `store` are already imported):

```go
func TestPostEmailPreservesDisplayName(t *testing.T) {
	f := setup(t, true)
	body := `{"from":"Atelier Cornelia <website@example.com>","to":"Jens de Rond <u@dest.test>","subject":"Hi","text":"yo"}`
	resp := f.post(t, body, f.token, "")
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		t.Fatalf("status = %d, want 202", resp.StatusCode)
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	e, err := f.store.GetEmail(out.ID)
	if err != nil {
		t.Fatal(err)
	}
	if e.FromName != "Atelier Cornelia" || e.ToName != "Jens de Rond" {
		t.Errorf("names: from=%q to=%q", e.FromName, e.ToName)
	}
	if e.From != "website@example.com" || e.To != "u@dest.test" {
		t.Errorf("routing addrs must be bare: from=%q to=%q", e.From, e.To)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/api/ -run TestPostEmailPreservesDisplayName`
Expected: FAIL — `e.FromName`/`e.ToName` are empty (names not captured/stored yet).

- [ ] **Step 3: Capture, validate, and store the names**

In `internal/api/api.go`, inside `postEmail`, after the existing `req.ReplyTo` validation block and before the `for name, value := range req.Headers` loop, add ingress validation of the composed header values:

```go
	if err := delivery.ValidateHeaderValue("From", delivery.FormatAddress(from.Name, from.Address)); err != nil {
		jsonError(w, 422, "invalid from: "+err.Error())
		return
	}
	if err := delivery.ValidateHeaderValue("To", delivery.FormatAddress(to.Name, to.Address)); err != nil {
		jsonError(w, 422, "invalid to: "+err.Error())
		return
	}
```

Then update the `enqueueOrReplay` call to pass the names (add `FromName`/`ToName`):

```go
	id, status, replay, err := enqueueOrReplay(s.Store, &store.Email{
		APIKeyID: k.ID, DomainID: domain.ID,
		From: from.Address, To: to.Address, FromName: from.Name, ToName: to.Name, ReplyTo: req.ReplyTo,
		Subject: req.Subject, BodyHTML: req.HTML, BodyText: req.Text,
		HeadersJSON: headersJSON, IdempotencyKey: idemKey,
	})
```

- [ ] **Step 4: Run the api tests to verify they pass**

Run: `go test ./internal/api/`
Expected: PASS — new test plus all existing api tests.

- [ ] **Step 5: Full build, vet, and test**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all PASS (matches CI).

- [ ] **Step 6: Commit**

```bash
git add internal/api/api.go internal/api/api_test.go
git commit -m "feat(api): preserve From/To display names from the request"
```

---

## Notes for the implementer

- **Do not** touch `internal/delivery/sender.go`, MX lookup, from-domain match, or `SignMessage`'s `HeaderKeys` — routing and DKIM stay on the bare address by design. The `From` header (now with display name) is still signed as-written because `write("From", ...)` runs before `SignMessage`.
- `Reply-To` already preserves display names; leave it alone.
- Admin UI display of the name is intentionally out of scope — `scanEmail` populates the fields, templates ignore them, nothing breaks.
