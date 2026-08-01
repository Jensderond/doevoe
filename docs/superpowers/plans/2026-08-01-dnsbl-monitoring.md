# DNSBL Blacklist Monitoring Implementation Plan (Phase 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Hourly DNS-blacklist checks for the egress IP and every verified domain, with transition-based admin alerts, persistent current status + append-only history, and a dashboard block.

**Architecture:** A new pure `internal/dnsbl` package (fake-resolver-testable, mirroring `internal/dnscheck`) classifies each (target, zone) lookup as Listed / NotListed / Indeterminate. A new hourly loop in `cmd/doevoe/main.go` (sibling of `recheckDNSLoop`) persists only determinate results via `store.RecordBlocklistCheck`, which returns the transition ("listed"/"cleared"/none); transitions trigger `notify.Notifier` emails through the existing fail-open enqueue path. The admin dashboard reads the stored status — no live DNS on page load.

**Tech Stack:** Go stdlib only (`net`, `context`, `database/sql`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-01-dmarc-dnsbl-monitoring-design.md` (Phase 1 sections). Phase 2 (DMARC ingestion) is a separate plan.

## Global Constraints

- No new Go module dependencies.
- `go vet ./...` and `go test ./...` must pass after every task (this is CI).
- Timestamps are RFC3339 strings via `store.Now()` / `store.FmtTime()` — never SQLite time types.
- **Indeterminate verdicts are never persisted and never alerted** (same invariant as `dnscheck.Result.Indeterminate`). Every task touching verdicts must preserve this; the reason belongs in a comment next to the code (project convention: money-quote invariants live near the code they constrain).
- The store runs with `db.SetMaxOpenConns(1)`. Inside a transaction, every statement MUST go through the `tx` handle — a `s.db.Query` while a tx is open deadlocks (the tx holds the only connection).
- New tables go into the `schema` constant with `CREATE TABLE IF NOT EXISTS` only; the `migrate()` ALTER pattern is for new *columns* on existing tables and is not needed here.

---

### Task 1: `internal/dnsbl` package

**Files:**
- Create: `internal/dnsbl/dnsbl.go`
- Test: `internal/dnsbl/dnsbl_test.go`

**Interfaces:**
- Consumes: nothing from this codebase.
- Produces (used by Task 4):
  - `type Resolver interface { LookupHost(ctx context.Context, host string) ([]string, error) }` (satisfied by `net.DefaultResolver`)
  - `type Verdict int` with constants `NotListed`, `Listed`, `Indeterminate`
  - `type Status struct { Target, Zone string; Verdict Verdict; Response string }`
  - `func Check(ctx context.Context, r Resolver, egressIP string, domains []string) []Status`

- [ ] **Step 1: Write the failing tests**

```go
package dnsbl

import (
	"context"
	"net"
	"testing"
)

type fakeResolver struct {
	answers map[string][]string // query name -> A answers
	errs    map[string]error    // query name -> lookup error
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if err, ok := f.errs[host]; ok {
		return nil, err
	}
	if a, ok := f.answers[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// one status per (target, zone) pair, keyed for easy lookup
func byZone(t *testing.T, statuses []Status, target, zone string) Status {
	t.Helper()
	for _, st := range statuses {
		if st.Target == target && st.Zone == zone {
			return st
		}
	}
	t.Fatalf("no status for %s / %s in %+v", target, zone, statuses)
	return Status{}
}

func TestCheckVerdicts(t *testing.T) {
	r := fakeResolver{
		answers: map[string][]string{
			// egress IP 203.0.113.7 reversed = 7.113.0.203
			"7.113.0.203.zen.spamhaus.org":       {"127.0.0.2"},       // listed (SBL)
			"7.113.0.203.b.barracudacentral.org": {"127.255.255.254"}, // rate-limited -> indeterminate
			// bl.spamcop.net: no entry -> NXDOMAIN -> not listed
			"bad.example.dbl.spamhaus.org":    {"127.0.1.2"},   // domain listed
			"err.example.dbl.spamhaus.org":    {"127.0.1.255"}, // DBL error code -> indeterminate
			"wild.example.dbl.spamhaus.org":   {"216.58.1.1"},  // ISP wildcard DNS -> indeterminate
			"bad.example.multi.surbl.org":     {"127.0.0.8"},   // SURBL bitmask -> listed
		},
		errs: map[string]error{
			"err.example.multi.surbl.org": &net.DNSError{Err: "timeout", IsTimeout: true},
		},
	}
	statuses := Check(context.Background(), r, "203.0.113.7",
		[]string{"bad.example", "err.example", "wild.example"})

	// 3 IP zones for the egress IP + 2 domain zones x 3 domains = 9 statuses
	if len(statuses) != 9 {
		t.Fatalf("want 9 statuses, got %d: %+v", len(statuses), statuses)
	}
	cases := []struct {
		target, zone string
		want         Verdict
	}{
		{"203.0.113.7", "zen.spamhaus.org", Listed},
		{"203.0.113.7", "bl.spamcop.net", NotListed},
		{"203.0.113.7", "b.barracudacentral.org", Indeterminate},
		{"bad.example", "dbl.spamhaus.org", Listed},
		{"bad.example", "multi.surbl.org", Listed},
		{"err.example", "dbl.spamhaus.org", Indeterminate},
		{"err.example", "multi.surbl.org", Indeterminate},
		{"wild.example", "dbl.spamhaus.org", Indeterminate},
		{"wild.example", "multi.surbl.org", NotListed},
	}
	for _, c := range cases {
		if got := byZone(t, statuses, c.target, c.zone).Verdict; got != c.want {
			t.Errorf("%s / %s: verdict = %v, want %v", c.target, c.zone, got, c.want)
		}
	}
	if st := byZone(t, statuses, "203.0.113.7", "zen.spamhaus.org"); st.Response != "127.0.0.2" {
		t.Errorf("listed Response = %q, want the answering A record", st.Response)
	}
}

func TestCheckZenPBLCodeIsListed(t *testing.T) {
	// 127.0.0.10/11 are Spamhaus PBL ("policy: dynamic/residential IP") —
	// recipient servers reject on it, so it must count as listed.
	r := fakeResolver{answers: map[string][]string{
		"7.113.0.203.zen.spamhaus.org": {"127.0.0.10"},
	}}
	statuses := Check(context.Background(), r, "203.0.113.7", nil)
	if got := byZone(t, statuses, "203.0.113.7", "zen.spamhaus.org").Verdict; got != Listed {
		t.Errorf("PBL code: verdict = %v, want Listed", got)
	}
}

func TestCheckBadEgressIPIsIndeterminate(t *testing.T) {
	statuses := Check(context.Background(), fakeResolver{}, "not-an-ip", nil)
	if len(statuses) != 3 {
		t.Fatalf("want 3 IP-zone statuses, got %d", len(statuses))
	}
	for _, st := range statuses {
		if st.Verdict != Indeterminate {
			t.Errorf("%s: verdict = %v, want Indeterminate", st.Zone, st.Verdict)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/dnsbl/ -v`
Expected: FAIL to build — `Check`, `Status`, `Verdict` undefined.

- [ ] **Step 3: Write the implementation**

```go
// Package dnsbl checks whether the egress IP or a sending domain is listed
// on a fixed set of DNS blacklists. It mirrors internal/dnscheck's shape:
// pure functions over an injected Resolver so tests use a fake, and a
// three-way verdict that separates "definitely (not) listed" from "cannot
// tell right now".
package dnsbl

import (
	"context"
	"errors"
	"net"
	"strings"
)

// Resolver is the subset of *net.Resolver we need; net.DefaultResolver
// satisfies it.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type Verdict int

const (
	// NotListed is the healthy answer: the zone returned NXDOMAIN.
	NotListed Verdict = iota
	// Listed means the zone answered inside its documented listing range.
	Listed
	// Indeterminate means the lookup failed or answered outside the zone's
	// listing range (Spamhaus public-resolver/rate-limit codes, ISP wildcard
	// DNS, timeouts). Callers must not persist or alert on Indeterminate:
	// Spamhaus deliberately refuses queries via public resolvers
	// (Google/Cloudflare DNS) with 127.255.255.x codes, so treating those as
	// "listed" would give every such install a permanent false alarm — the
	// same fail-open-on-transient rule as dnscheck.Result.Indeterminate.
	Indeterminate
)

// Status is the outcome of checking one target against one zone.
type Status struct {
	Target   string // the IP or domain that was checked
	Zone     string
	Verdict  Verdict
	Response string // first A answer when the zone answered; "" on NXDOMAIN/error
}

// zone describes one blacklist: its DNS suffix, whether it takes reversed
// IPs or domain names, and which 127.0.0.0/8 answers mean "listed".
// Everything else inside 127/8 (error/diagnostic codes) and everything
// outside it (wildcard resolvers) is Indeterminate.
type zone struct {
	name   string
	forIP  bool
	listed func(o [4]byte) bool // o = the answer's IPv4 octets
}

var zones = []zone{
	{"zen.spamhaus.org", true, func(o [4]byte) bool {
		return o[1] == 0 && o[2] == 0 && o[3] >= 2 && o[3] <= 11 // SBL/CSS/XBL/PBL
	}},
	{"bl.spamcop.net", true, func(o [4]byte) bool {
		return o[1] == 0 && o[2] == 0 && o[3] == 2
	}},
	{"b.barracudacentral.org", true, func(o [4]byte) bool {
		return o[1] == 0 && o[2] == 0 && o[3] == 2
	}},
	{"dbl.spamhaus.org", false, func(o [4]byte) bool {
		return o[1] == 0 && o[2] == 1 && o[3] < 255 // 127.0.1.255 = "IP queries prohibited" error
	}},
	{"multi.surbl.org", false, func(o [4]byte) bool {
		return o[1] == 0 && o[2] == 0 && o[3] >= 2 // bitmask of SURBL sub-lists
	}},
}

// Check queries every IP zone for egressIP and every domain zone for each
// domain, returning one Status per (target, zone) pair.
func Check(ctx context.Context, r Resolver, egressIP string, domains []string) []Status {
	var out []Status
	rev, revOK := reverseIPv4(egressIP)
	for _, z := range zones {
		if z.forIP {
			if !revOK {
				out = append(out, Status{Target: egressIP, Zone: z.name, Verdict: Indeterminate})
				continue
			}
			out = append(out, query(ctx, r, z, egressIP, rev+"."+z.name))
			continue
		}
		for _, d := range domains {
			out = append(out, query(ctx, r, z, d, d+"."+z.name))
		}
	}
	return out
}

func query(ctx context.Context, r Resolver, z zone, target, name string) Status {
	st := Status{Target: target, Zone: z.name}
	addrs, err := r.LookupHost(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			st.Verdict = NotListed // NXDOMAIN: the one genuinely healthy answer
			return st
		}
		st.Verdict = Indeterminate // timeout, SERVFAIL, network error, ...
		return st
	}
	if len(addrs) == 0 {
		st.Verdict = Indeterminate
		return st
	}
	st.Response = addrs[0]
	st.Verdict = classify(z, addrs)
	return st
}

func classify(z zone, addrs []string) Verdict {
	for _, a := range addrs {
		ip4 := net.ParseIP(a).To4()
		if ip4 == nil || ip4[0] != 127 {
			// Not a loopback answer: an intercepting/wildcard resolver, not
			// the blacklist speaking. Cannot conclude anything.
			return Indeterminate
		}
		if z.listed([4]byte(ip4)) {
			return Listed
		}
	}
	// Loopback answers outside the listing range: Spamhaus error codes
	// (127.255.255.x = public resolver / rate limited / blocked) and
	// anything undocumented. Never treat these as listed — see Indeterminate.
	return Indeterminate
}

// reverseIPv4 turns "203.0.113.7" into "7.113.0.203". ok is false for
// anything that is not a plain IPv4 address.
func reverseIPv4(s string) (string, bool) {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	o := strings.Split(ip.To4().String(), ".")
	return o[3] + "." + o[2] + "." + o[1] + "." + o[0], true
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dnsbl/ -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Vet and commit**

Run: `go vet ./...`

```bash
git add internal/dnsbl/
git commit -m "feat(dnsbl): blacklist check package with indeterminate handling"
```

---

### Task 2: store — blocklist status + events

**Files:**
- Modify: `internal/store/store.go` (append two tables to the `schema` constant, before the closing backtick)
- Create: `internal/store/blocklist.go`
- Test: `internal/store/blocklist_test.go`

**Interfaces:**
- Consumes: `Store.db`, `store.Now()` conventions.
- Produces (used by Tasks 4 and 5):
  - `type BlocklistStatus struct { Target, Zone string; Listed bool; Since, LastChecked string }`
  - `type BlocklistEvent struct { ID int64; Target, Zone string; Listed bool; OccurredAt string }`
  - `func (s *Store) RecordBlocklistCheck(target, zone string, listed bool, now string) (transition string, err error)` — transition is `"listed"`, `"cleared"`, or `""`
  - `func (s *Store) ListBlocklistStatus() ([]BlocklistStatus, error)` — all rows, listed first, then by target/zone
  - `func (s *Store) RecentBlocklistEvents(limit int) ([]BlocklistEvent, error)` — newest first

- [ ] **Step 1: Write the failing tests**

```go
package store

import (
	"path/filepath"
	"testing"
)

func blStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRecordBlocklistCheckTransitions(t *testing.T) {
	s := blStore(t)

	// First sight, clean: status row, no event, no transition.
	tr, err := s.RecordBlocklistCheck("203.0.113.7", "zen.spamhaus.org", false, "2026-08-01T10:00:00Z")
	if err != nil || tr != "" {
		t.Fatalf("first clean check: transition=%q err=%v, want \"\" nil", tr, err)
	}
	// Steady state: still no transition, last_checked advances.
	tr, _ = s.RecordBlocklistCheck("203.0.113.7", "zen.spamhaus.org", false, "2026-08-01T11:00:00Z")
	if tr != "" {
		t.Fatalf("steady clean: transition=%q, want \"\"", tr)
	}
	// Gets listed: transition + event.
	tr, _ = s.RecordBlocklistCheck("203.0.113.7", "zen.spamhaus.org", true, "2026-08-01T12:00:00Z")
	if tr != "listed" {
		t.Fatalf("newly listed: transition=%q, want \"listed\"", tr)
	}
	// Still listed: steady state again.
	tr, _ = s.RecordBlocklistCheck("203.0.113.7", "zen.spamhaus.org", true, "2026-08-01T13:00:00Z")
	if tr != "" {
		t.Fatalf("steady listed: transition=%q, want \"\"", tr)
	}
	// Cleared.
	tr, _ = s.RecordBlocklistCheck("203.0.113.7", "zen.spamhaus.org", false, "2026-08-01T14:00:00Z")
	if tr != "cleared" {
		t.Fatalf("cleared: transition=%q, want \"cleared\"", tr)
	}

	sts, err := s.ListBlocklistStatus()
	if err != nil || len(sts) != 1 {
		t.Fatalf("status rows: %v err=%v, want exactly 1", sts, err)
	}
	st := sts[0]
	if st.Listed || st.Since != "2026-08-01T14:00:00Z" || st.LastChecked != "2026-08-01T14:00:00Z" {
		t.Errorf("status = %+v; want unlisted, since/last_checked at the clear time", st)
	}

	evs, err := s.RecentBlocklistEvents(10)
	if err != nil || len(evs) != 2 {
		t.Fatalf("events: %v err=%v, want exactly 2 (listed, cleared)", evs, err)
	}
	// Newest first.
	if evs[0].Listed || !evs[1].Listed {
		t.Errorf("event order/content wrong: %+v", evs)
	}
	if evs[1].OccurredAt != "2026-08-01T12:00:00Z" || evs[0].OccurredAt != "2026-08-01T14:00:00Z" {
		t.Errorf("event timestamps wrong: %+v", evs)
	}
}

func TestRecordBlocklistCheckFirstSightListed(t *testing.T) {
	s := blStore(t)
	// First-ever check already listed must alert (transition "listed"):
	// the operator has never been told about this listing.
	tr, err := s.RecordBlocklistCheck("bad.example", "dbl.spamhaus.org", true, "2026-08-01T10:00:00Z")
	if err != nil || tr != "listed" {
		t.Fatalf("first-sight listed: transition=%q err=%v, want \"listed\" nil", tr, err)
	}
	evs, _ := s.RecentBlocklistEvents(10)
	if len(evs) != 1 || !evs[0].Listed {
		t.Fatalf("want one listed event, got %+v", evs)
	}
}

func TestListBlocklistStatusOrdersListedFirst(t *testing.T) {
	s := blStore(t)
	s.RecordBlocklistCheck("a.example", "multi.surbl.org", false, "2026-08-01T10:00:00Z")
	s.RecordBlocklistCheck("z.example", "dbl.spamhaus.org", true, "2026-08-01T10:00:00Z")
	sts, err := s.ListBlocklistStatus()
	if err != nil || len(sts) != 2 {
		t.Fatalf("got %v err=%v", sts, err)
	}
	if !sts[0].Listed {
		t.Errorf("listed rows must sort first: %+v", sts)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/ -run Blocklist -v`
Expected: FAIL to build — `RecordBlocklistCheck` undefined.

- [ ] **Step 3: Add the tables to the schema constant**

In `internal/store/store.go`, append inside the `schema` constant (after the `notify_pending_failures` table, before the closing backtick):

```sql
CREATE TABLE IF NOT EXISTS blocklist_status (
  target TEXT NOT NULL,
  zone TEXT NOT NULL,
  listed INTEGER NOT NULL,
  since TEXT NOT NULL,
  last_checked TEXT NOT NULL,
  PRIMARY KEY (target, zone)
);
CREATE TABLE IF NOT EXISTS blocklist_events (
  id INTEGER PRIMARY KEY,
  target TEXT NOT NULL,
  zone TEXT NOT NULL,
  listed INTEGER NOT NULL,
  occurred_at TEXT NOT NULL
);
```

No `migrate()` entry needed: these are new tables, so `CREATE TABLE IF NOT EXISTS` covers both fresh and existing DBs.

- [ ] **Step 4: Write the implementation**

Create `internal/store/blocklist.go`:

```go
package store

import (
	"database/sql"
	"errors"
)

// BlocklistStatus is the current listing state of one (target, zone) pair.
// Target is the egress IP or a domain name; Since is when the current
// Listed value began; LastChecked is the last determinate check.
type BlocklistStatus struct {
	Target, Zone       string
	Listed             bool
	Since, LastChecked string
}

// BlocklistEvent is one listing transition (append-only history).
type BlocklistEvent struct {
	ID           int64
	Target, Zone string
	Listed       bool
	OccurredAt   string
}

// RecordBlocklistCheck persists a determinate check result and reports the
// transition it caused: "listed" (was clean or never seen, now listed),
// "cleared" (was listed, now clean), or "" (steady state). The status upsert
// and the transition event are one transaction so history can never disagree
// with current state. Callers must not call this for indeterminate verdicts
// (see dnsbl.Indeterminate) — only genuine answers belong in the history.
//
// Transitions — not per-check snapshots — are the stored grain: hourly
// snapshots would be thousands of redundant "still clear" rows per month,
// while transitions plus last_checked reconstruct the timeline losslessly.
func (s *Store) RecordBlocklistCheck(target, zone string, listed bool, now string) (string, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	// MaxOpenConns(1): every statement in here must use tx, never s.db,
	// or the query blocks forever waiting for the connection tx holds.
	var prev bool
	known := true
	err = tx.QueryRow(`SELECT listed FROM blocklist_status WHERE target=? AND zone=?`,
		target, zone).Scan(&prev)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return "", err
		}
		known = false
	}

	transition := ""
	switch {
	case !known && listed:
		transition = "listed" // first sight already listed: operator was never told
	case known && listed && !prev:
		transition = "listed"
	case known && !listed && prev:
		transition = "cleared"
	}

	if known && transition == "" {
		if _, err := tx.Exec(`UPDATE blocklist_status SET last_checked=? WHERE target=? AND zone=?`,
			now, target, zone); err != nil {
			return "", err
		}
	} else {
		if _, err := tx.Exec(`INSERT INTO blocklist_status (target, zone, listed, since, last_checked)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(target, zone) DO UPDATE SET listed=excluded.listed,
				since=excluded.since, last_checked=excluded.last_checked`,
			target, zone, boolInt(listed), now, now); err != nil {
			return "", err
		}
	}
	if transition != "" {
		if _, err := tx.Exec(`INSERT INTO blocklist_events (target, zone, listed, occurred_at)
			VALUES (?, ?, ?, ?)`, target, zone, boolInt(listed), now); err != nil {
			return "", err
		}
	}
	return transition, tx.Commit()
}

func (s *Store) ListBlocklistStatus() ([]BlocklistStatus, error) {
	rows, err := s.db.Query(`SELECT target, zone, listed, since, last_checked
		FROM blocklist_status ORDER BY listed DESC, target, zone`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlocklistStatus
	for rows.Next() {
		var st BlocklistStatus
		var listed int
		if err := rows.Scan(&st.Target, &st.Zone, &listed, &st.Since, &st.LastChecked); err != nil {
			return nil, err
		}
		st.Listed = listed != 0
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *Store) RecentBlocklistEvents(limit int) ([]BlocklistEvent, error) {
	rows, err := s.db.Query(`SELECT id, target, zone, listed, occurred_at
		FROM blocklist_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BlocklistEvent
	for rows.Next() {
		var ev BlocklistEvent
		var listed int
		if err := rows.Scan(&ev.ID, &ev.Target, &ev.Zone, &listed, &ev.OccurredAt); err != nil {
			return nil, err
		}
		ev.Listed = listed != 0
		out = append(out, ev)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
```

Note: if a `boolInt` (or equivalent) helper already exists in the store package, use the existing one instead of adding a duplicate — check with `grep -rn "func boolInt" internal/store/` first.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/ -run Blocklist -v`
Expected: PASS (3 tests). Then run the full package: `go test ./internal/store/` — everything else must still pass (schema change is additive).

- [ ] **Step 6: Vet and commit**

Run: `go vet ./...`

```bash
git add internal/store/store.go internal/store/blocklist.go internal/store/blocklist_test.go
git commit -m "feat(store): blocklist status + append-only transition events"
```

---

### Task 3: notify — blocklist hit / cleared notifications

**Files:**
- Modify: `internal/notify/notifier.go` (add two methods after `KeyRevoked`, around line 87)
- Test: `internal/notify/notifier_test.go` (append)

**Interfaces:**
- Consumes: the existing `(n *Notifier) enqueue(subject, body string) (bool, error)` fail-open helper and the `fixture(t, systemVerified bool)` test helper already in `notifier_test.go`.
- Produces (used by Task 4):
  - `func (n *Notifier) BlocklistHit(target, zone string)`
  - `func (n *Notifier) BlocklistCleared(target, zone string)`

- [ ] **Step 1: Write the failing test**

Append to `internal/notify/notifier_test.go`:

```go
func TestBlocklistNotifications(t *testing.T) {
	s, n, _ := fixture(t, true)

	n.BlocklistHit("203.0.113.7", "zen.spamhaus.org")
	emails := systemEmails(t, s)
	if len(emails) != 1 {
		t.Fatalf("after hit: %d system emails, want 1", len(emails))
	}
	if !strings.Contains(emails[0].Subject, "zen.spamhaus.org") ||
		!strings.Contains(emails[0].BodyText, "203.0.113.7") {
		t.Errorf("hit email lacks zone/target: subject=%q body=%q", emails[0].Subject, emails[0].BodyText)
	}

	n.BlocklistCleared("203.0.113.7", "zen.spamhaus.org")
	emails = systemEmails(t, s)
	if len(emails) != 2 {
		t.Fatalf("after clear: %d system emails, want 2", len(emails))
	}
}

func TestBlocklistNotificationsFailOpenUnverified(t *testing.T) {
	s, n, _ := fixture(t, false) // system domain not verified
	n.BlocklistHit("203.0.113.7", "zen.spamhaus.org")
	if got := len(systemEmails(t, s)); got != 0 {
		t.Fatalf("unverified system domain must skip silently, got %d emails", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/notify/ -run Blocklist -v`
Expected: FAIL to build — `BlocklistHit` undefined.

- [ ] **Step 3: Write the implementation**

Add to `internal/notify/notifier.go` after `KeyRevoked` (mirrors its shape exactly — fire-and-forget, log on error):

```go
// BlocklistHit and BlocklistCleared are called by the blocklist loop on a
// listing transition (the stored previous state in blocklist_status is the
// arm/re-arm mechanism, so each fires at most once per transition).

func (n *Notifier) BlocklistHit(target, zone string) {
	if _, err := n.enqueue("doevoe: "+target+" is LISTED on "+zone,
		fmt.Sprintf("%s is now listed on the %s blacklist.\n\nRecipient servers consulting this list may reject or junk-folder mail. Check the listing and request delisting via the operator's site.\n\n%s/admin/\n", target, zone, n.BaseURL)); err != nil {
		slog.Error("notifier: blocklist hit notification failed", "target", target, "zone", zone, "err", err)
	}
}

func (n *Notifier) BlocklistCleared(target, zone string) {
	if _, err := n.enqueue("doevoe: "+target+" delisted from "+zone,
		fmt.Sprintf("%s is no longer listed on the %s blacklist.\n\n%s/admin/\n", target, zone, n.BaseURL)); err != nil {
		slog.Error("notifier: blocklist cleared notification failed", "target", target, "zone", zone, "err", err)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/notify/ -v`
Expected: PASS, including all pre-existing tests.

- [ ] **Step 5: Vet and commit**

Run: `go vet ./...`

```bash
git add internal/notify/notifier.go internal/notify/notifier_test.go
git commit -m "feat(notify): blocklist listed/delisted notifications"
```

---

### Task 4: wire the hourly blocklist loop in main.go

**Files:**
- Modify: `cmd/doevoe/main.go` (new goroutine next to the `recheckDNSLoop` one, ~line 90; new function after `recheckDNSLoop`; add `"doevoe/internal/dnsbl"` import)

**Interfaces:**
- Consumes: `dnsbl.Check` (Task 1), `store.RecordBlocklistCheck` (Task 2), `notifier.BlocklistHit`/`BlocklistCleared` (Task 3), existing `s.ListDomains()` / `d.Verified()`.
- Produces: nothing consumed by later tasks (Task 5 reads the store directly).

`main.go` has no test file (the loops it hosts, like `recheckDNSLoop`, are thin glue over tested packages — this loop follows that precedent), so this task is verified by build + vet + full test suite.

- [ ] **Step 1: Add the loop function**

After `recheckDNSLoop` in `cmd/doevoe/main.go`:

```go
// blocklistLoop periodically checks the egress IP and every verified domain
// against the DNS blacklists in internal/dnsbl, persists determinate
// results, and notifies on listing transitions. Unverified domains are
// skipped: they can't send, so their listing status is noise.
//
// Unlike recheckDNSLoop it runs once shortly after boot: there is no manual
// "check now" trigger for blacklists (domain verify covers DNS records), so
// without the initial run a fresh install would show nothing for an hour.
func blocklistLoop(ctx context.Context, s *store.Store, n *notify.Notifier, egressIP string) {
	run := func() {
		domains, err := s.ListDomains()
		if err != nil {
			slog.Error("blocklist: list domains", "err", err)
			return
		}
		var names []string
		for _, d := range domains {
			if d.Verified() {
				names = append(names, d.Name)
			}
		}
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		statuses := dnsbl.Check(checkCtx, net.DefaultResolver, egressIP, names)
		cancel()
		for _, st := range statuses {
			if st.Verdict == dnsbl.Indeterminate {
				// Transient failure or a Spamhaus "public resolver" code:
				// not a genuine answer, so never persisted and never
				// alerted — same rule as the indeterminate DNS rechecks.
				slog.Warn("blocklist check indeterminate; not persisting",
					"target", st.Target, "zone", st.Zone, "response", st.Response)
				continue
			}
			transition, err := s.RecordBlocklistCheck(st.Target, st.Zone, st.Verdict == dnsbl.Listed, store.Now())
			if err != nil {
				slog.Error("blocklist: record check", "target", st.Target, "zone", st.Zone, "err", err)
				continue
			}
			switch transition {
			case "listed":
				slog.Warn("blocklist: newly listed", "target", st.Target, "zone", st.Zone, "response", st.Response)
				n.BlocklistHit(st.Target, st.Zone)
			case "cleared":
				slog.Info("blocklist: delisted", "target", st.Target, "zone", st.Zone)
				n.BlocklistCleared(st.Target, st.Zone)
			}
		}
	}

	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
	}
	run()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
```

- [ ] **Step 2: Start the goroutine and add the import**

Add `"doevoe/internal/dnsbl"` to the import block. In `main()`, after the `recheckDNSLoop` goroutine:

```go
	wg.Add(1)
	go func() {
		defer wg.Done()
		blocklistLoop(ctx, s, notifier, cfg.EgressIP)
	}()
```

- [ ] **Step 3: Build, vet, full test suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add cmd/doevoe/main.go
git commit -m "feat: hourly DNS blacklist monitoring loop with transition alerts"
```

---

### Task 5: dashboard blacklist status block

**Files:**
- Modify: `internal/admin/admin.go` — `dashboard` handler (~line 340): fetch status + events, add to the `render` data map
- Modify: `internal/admin/templates/dashboard.html` — new section after the KPI block
- Test: `internal/admin/admin_test.go` (append)

**Interfaces:**
- Consumes: `store.ListBlocklistStatus()`, `store.RecentBlocklistEvents(10)`, `store.RecordBlocklistCheck` (to seed in tests), the `adminFixture`/`login` helpers already in `admin_test.go`.
- Produces: nothing — leaf task.

- [ ] **Step 1: Write the failing test**

Append to `internal/admin/admin_test.go`:

```go
func TestDashboardBlocklistBlock(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")

	// No checks recorded yet.
	body := getBody(t, c, srv.URL+"/admin/")
	if !strings.Contains(body, "No blacklist checks recorded yet") {
		t.Errorf("empty state missing from dashboard")
	}

	// All clear.
	s.RecordBlocklistCheck("203.0.113.7", "zen.spamhaus.org", false, "2026-08-01T10:00:00Z")
	body = getBody(t, c, srv.URL+"/admin/")
	if !strings.Contains(body, "All clear") {
		t.Errorf("all-clear state missing from dashboard")
	}

	// Active listing shows target + zone, and the transition appears in history.
	s.RecordBlocklistCheck("client.example", "dbl.spamhaus.org", true, "2026-08-01T11:00:00Z")
	body = getBody(t, c, srv.URL+"/admin/")
	if !strings.Contains(body, "dbl.spamhaus.org") || !strings.Contains(body, "client.example") {
		t.Errorf("active listing missing from dashboard")
	}
	if !strings.Contains(body, "Listed") {
		t.Errorf("event history missing from dashboard")
	}
}
```

If `admin_test.go` has no `getBody` helper (check with `grep -n "func getBody" internal/admin/admin_test.go`), add it:

```go
func getBody(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
```

If an equivalent helper already exists under another name, use that one and skip adding `getBody`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/admin/ -run DashboardBlocklist -v`
Expected: FAIL — dashboard body lacks the blocklist strings.

- [ ] **Step 3: Extend the dashboard handler**

In `internal/admin/admin.go`'s `dashboard` func, after the `reasons` fetch (~line 361):

```go
	blStatus, _ := a.Store.ListBlocklistStatus()
	blEvents, _ := a.Store.RecentBlocklistEvents(10)
	var blListings []store.BlocklistStatus
	blLastChecked := ""
	for _, st := range blStatus {
		if st.Listed {
			blListings = append(blListings, st)
		}
		if st.LastChecked > blLastChecked { // RFC3339 sorts lexicographically
			blLastChecked = st.LastChecked
		}
	}
```

And extend the `render` data map:

```go
	a.render(w, r, "dashboard", map[string]any{
		"Days":               days,
		"Summary":            summary,
		"DataJSON":           template.JS(blob),
		"BlocklistChecked":   len(blStatus) > 0,
		"BlocklistListings":  blListings,
		"BlocklistLastCheck": blLastChecked,
		"BlocklistEvents":    blEvents,
	})
```

- [ ] **Step 4: Add the template block**

In `internal/admin/templates/dashboard.html`, after the `.kpis` div (line 16):

```html
<h2 class="section-title">Blacklists</h2>
<div class="card">
  {{if not .BlocklistChecked}}
    <p class="muted">No blacklist checks recorded yet — the first check runs about a minute after startup.</p>
  {{else if .BlocklistListings}}
    <table>
      <thead><tr><th>Target</th><th>Blacklist</th><th>Listed since</th></tr></thead>
      <tbody>
      {{range .BlocklistListings}}
        <tr><td>{{.Target}}</td><td>{{.Zone}}</td><td>{{.Since}}</td></tr>
      {{end}}
      </tbody>
    </table>
  {{else}}
    <p>All clear — last checked {{.BlocklistLastCheck}}.</p>
  {{end}}
  {{if .BlocklistEvents}}
    <h3 class="section-title">History</h3>
    <ul>
    {{range .BlocklistEvents}}
      <li>{{.OccurredAt}} — {{.Target}} {{if .Listed}}Listed on{{else}}Cleared from{{end}} {{.Zone}}</li>
    {{end}}
    </ul>
  {{end}}
</div>
```

Match surrounding markup conventions: if the existing templates use different class names for tables/muted text (check `emails.html` for the table markup and `layout.html`/`static/*.css` for a muted/empty-state class), reuse those instead of inventing new ones.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/admin/ -v`
Expected: PASS, including all pre-existing dashboard tests.

- [ ] **Step 6: Vet, full suite, commit**

Run: `go vet ./... && go test ./...`

```bash
git add internal/admin/admin.go internal/admin/templates/dashboard.html internal/admin/admin_test.go
git commit -m "feat(admin): blacklist status and history on the dashboard"
```

---

### Task 6: README + spec status update

**Files:**
- Modify: `README.md` (feature list / how-it-works section — add one short paragraph on blacklist monitoring: what's checked, hourly cadence, transition alerts, dashboard block)
- Modify: `docs/superpowers/specs/2026-08-01-dmarc-dnsbl-monitoring-design.md` (mark Phase 1 as implemented in the Status line: `**Status:** Phase 1 implemented; Phase 2 (DMARC ingestion) pending`)

- [ ] **Step 1: Update README**

Read the README's existing feature/architecture wording first and match its tone. Content to convey: doevoe checks the egress IP against Spamhaus ZEN, SpamCop, and Barracuda, and every verified domain against Spamhaus DBL and SURBL, hourly; new listings and delistings email the admin; current status and listing history are on the dashboard; checks are skipped (not treated as listings) when the resolver can't give a definite answer — Spamhaus blocks public resolvers such as Google/Cloudflare DNS, so use the host's own resolver for reliable results.

- [ ] **Step 2: Update the spec status line**

- [ ] **Step 3: Commit**

```bash
git add README.md docs/superpowers/specs/2026-08-01-dmarc-dnsbl-monitoring-design.md
git commit -m "docs: document blacklist monitoring"
```
