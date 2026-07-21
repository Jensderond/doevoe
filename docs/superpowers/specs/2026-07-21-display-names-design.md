# Display names on From / To headers

**Date:** 2026-07-21
**Status:** Approved (design)
**Scope:** Preserve sender/recipient display names on outgoing `From` and `To`
headers. HTML bodies and multipart/alternative already work and are out of scope.

## Problem

The API accepts `"from": "Atelier Cornelia <website@ateliercornelia.nl>"`, but
`internal/api/api.go` stores only the bare address (`from.Address` / `to.Address`),
so the delivered message shows `From: website@ateliercornelia.nl` with no display
name. This is the documented v1 limitation in the README and CLAUDE.md.

`Reply-To` already preserves its display name (the raw request string is stored and
written to the header unchanged), so only `From` and `To` need work.

Not a problem to fix here: the message itself is technically healthy — a live
mail-tester run passed DKIM, SPF, and DMARC with a spam score of -0.2. A Gmail
delivery failure on a brand-new sending domain/IP is a reputation/warmup issue,
not a message-construction bug. See "Deliverability note" at the end.

## Constraint that drives the design

`from_addr` / `to_addr` do triple duty as the routing addresses:

- SMTP envelope `MAIL FROM` / `RCPT TO` (`internal/delivery/sender.go`)
- recipient MX lookup (`sender.go`: `e.To[LastIndex("@")+1:]`)
- from-domain match against the API key's domain (`api.go`)

All three require the **bare** address. The display name must therefore live
*alongside* the bare address, never inside these columns.

## Approach

Add dedicated `from_name` / `to_name` columns. Compose the RFC 5322 header at
build time from name + bare address; keep every routing consumer on the bare
address unchanged.

Rejected alternatives:
- Store a pre-formatted `"Name <addr>"` header string in new columns — redundant
  with the bare address, couples storage to RFC 5322 formatting.
- Store `"Name <addr>"` in `from_addr`/`to_addr` and re-parse the bare address at
  every routing site — changes the meaning of existing columns and pushes parsing
  into the send hot path.

## Changes

### 1. `internal/store`

- Add `FromName, ToName string` to the `Email` struct.
- Add `from_name` / `to_name` (`TEXT NOT NULL DEFAULT ''`) to the `emails` table
  in the `schema` constant, and to `emailCols`, `scanEmail`, and the
  `EnqueueEmail` INSERT column/value lists.
- **Migration.** `Open()` runs only `CREATE TABLE IF NOT EXISTS`, so an existing
  production DB never receives columns added to the schema constant, and scans
  would then fail. Add an idempotent `migrate()` step in `Open()` (after the
  `schema` exec) that runs `ALTER TABLE emails ADD COLUMN from_name …` and
  `… to_name …`, tolerating the SQLite `"duplicate column name"` error (which
  fresh DBs — already carrying the columns from the schema constant — will
  raise). This is the project's first migration; leave a comment establishing
  the pattern (a list of ALTER statements applied best-effort, duplicate-column
  errors ignored, anything else fatal).

### 2. `internal/delivery/message.go`

- Add `FormatAddress(name, addr string) string`: returns
  `(&mail.Address{Name: name, Address: addr}).String()` when `name != ""`, else
  the bare `addr`. `mail.Address.String()` RFC 2047-encodes non-ASCII names,
  quotes specials, and never emits raw CR/LF — injection-safe by construction.
- `BuildMessage` writes `From` / `To` via `FormatAddress(e.FromName, e.From)` and
  `FormatAddress(e.ToName, e.To)`, and validates the **composed** values with the
  existing `validateHeaderValue` (defense in depth, matching the current
  double-validation style).
- Unchanged and still bare: SMTP envelope, MX lookup, from-domain match, and DKIM
  signing (`From` stays in `SignOptions.HeaderKeys` and is signed exactly as
  written, display name included).
- Add the `net/mail` import.

### 3. `internal/api/api.go`

- Capture `from.Name` / `to.Name` from the existing `mail.ParseAddress` results
  and pass them as `FromName` / `ToName` on the enqueued `store.Email`.
- Validate `delivery.FormatAddress(...)` output with `delivery.ValidateHeaderValue`
  at ingress, preserving the "reject before queuing an unsendable email"
  invariant. (`FormatAddress` is exported from `internal/delivery` for this.)

## Testing

- `message_test`: display name renders as `"Atelier Cornelia" <website@…>`;
  non-ASCII name (e.g. `Café`) is RFC 2047-encoded; empty name yields the bare
  address unchanged; a crafted CR/LF name is rejected or neutralized (no raw
  CRLF in output).
- `api_test`: a request with `"Name <addr>"` stores `FromName`/`ToName`; the
  envelope address and from-domain match still use the bare address.
- `store_test`: `migrate()` is idempotent — opening twice succeeds, and opening a
  column-less DB then reopening adds the columns without error.
- All existing tests (bare-address path) continue to pass unchanged.

## Out of scope

- Showing the display name in the admin UI. `scanEmail` populates the new fields;
  templates simply ignore them, so nothing breaks. Can be added later.
- Any HTML / multipart work — already implemented.
- Any deliverability code changes.

## Deliverability note (guidance, not code)

The Gmail failure is almost certainly new-domain/IP reputation:

- `sending.roundtheweb.nl` / 88.198.108.167 has no sending history.
- `ateliercornelia.nl` publishes `p=quarantine`, so borderline mail is
  spam-foldered during warmup rather than bounced — consistent with "it failed."
- Send both `text` and `html` (multipart/alternative) rather than a single part;
  html-only mail is scored slightly worse by some filters.

Mitigations are operational (warm up volume gradually, keep DMARC/DKIM/SPF
passing, monitor Google Postmaster Tools), not code.
