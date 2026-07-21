# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

doevoe is a self-hosted transactional email API: a single Go binary that queues, DKIM-signs,
and delivers mail directly to recipient MX servers (no third-party ESP, no smarthost), with a
JSON send/status API and a server-rendered admin UI for domain/DKIM setup, API keys, and
delivery logs. Embedded SQLite is the only datastore.

## Commands

```bash
go build ./...                 # build everything
go run ./cmd/doevoe             # run the server (requires DOEVOE_* env vars, see .env.example)
go vet ./...                    # matches CI
go test ./...                   # matches CI
go test ./internal/delivery/... -run TestName -v   # single test in a package
go run ./cmd/seed-demo /tmp/somedir   # populate a scratch DB with demo data for screenshots (dev-only, not shipped)
```

CI (`.github/workflows/docker.yml`) runs `go vet ./...` and `go test ./...` on every push to
`main`, then builds and pushes the Docker image to `ghcr.io/<repo>` (tagged `latest` on main,
plus semver/sha tags).

There is no linter config beyond `go vet`; there's no Makefile.

## Architecture

Wiring lives entirely in `cmd/doevoe/main.go` — read it first to see how the pieces below are
connected. There's one `*store.Store` (SQLite) shared by everything; all cross-package
coordination goes through it plus a few injected function fields (dependency injection via
struct fields, not interfaces/DI framework):

- **`internal/store`** — the SQLite schema (embedded as a Go string constant) and all queries.
  `db.SetMaxOpenConns(1)` is deliberate: SQLite is single-writer, so this sidesteps
  `SQLITE_BUSY` entirely rather than adding retry logic. Timestamps are stored as RFC3339
  strings (`store.Now()` / `store.FmtTime()` / `store.ParseTime()`), not SQLite's native time
  type. `notify_pending_failures` / `notify_state` are how `internal/notify` persists
  cross-tick state without its own storage.
- **`internal/api`** — the public JSON API (`POST /api/v1/emails`, `GET /api/v1/emails/{id}`),
  bearer-token auth against `store.APIKey`. Validates everything it can up front (addresses,
  header values, from-domain match, domain verification) so a bad request never becomes a
  queued email that can never send. Idempotency-Key handling is check-then-insert with a
  fallback re-check on unique-constraint failure (`enqueueOrReplay`) since the two aren't
  atomic.
- **`internal/admin`** — server-rendered HTML admin UI (`html/template`, embedded
  `templates/*.html` + `static/*`), single-admin-password auth with a random session token
  cookie (`SameSite=Lax`, no CSRF token — see v1 scope notes in README). Owns domain
  create/verify, API key create/revoke, and the email list/detail/retry views.
- **`internal/delivery`** — the sending pipeline:
  - `worker.go`: polls `store.ClaimDue` on a ticker, delivers concurrently with a
    per-recipient-domain concurrency limit (semaphore per domain), recovers panics per-email
    so one bad email can't kill a tick, and reschedules on `backoff.go`'s fixed schedule
    (`1m → 5m → 15m → 1h → 4h → 12h → 24h`) or marks permanently failed once exhausted.
  - `sender.go`: does the actual SMTP — MX lookup (capped to `maxMXAttempts`), opportunistic
    STARTTLS with a forced post-handshake `Hello()` to surface bad certs immediately, and a
    hard per-Send socket-level deadline (`OverallTimeout`, wraps the *entire* dial+handshake+
    I/O, not just go-smtp's internal timers) that must stay well under the worker's
    stale-`sending` requeue window — these two constants are load-bearing together; read the
    comments on `staleSendingWindow` (worker.go) and `defaultOverallTimeout`/`commandTimeout`/
    `submissionTimeout` (sender.go) before changing either.
  - `classify.go`: SMTP 5xx (and "recipient domain doesn't exist" DNS errors) are permanent;
    everything else is temporary and retried.
  - `message.go`: builds and DKIM-signs the RFC 5322 message.
- **`internal/dkimkeys`** — DKIM keypair generation and DNS record text generation
  (`dkimkeys.Records`) shown in the admin UI.
- **`internal/dnscheck`** — looks up SPF/DKIM/DMARC TXT records and compares against expected
  values. Distinguishes a genuine "record missing" answer from a transient resolver failure
  (`Result.Indeterminate`) — callers (admin verify handler, hourly recheck loop in
  `main.go`) must never persist an indeterminate result, since that would flip an
  already-verified domain to unverified and fail-close its sends with 403 on a mere DNS blip.
- **`internal/notify`** — a one-minute-ticker loop (`Notifier.Run`) with three independent
  ticks: failure digest (batched, hourly cooldown), per-domain elevated-failure-rate alerts
  (arm/re-arm via `notify_state`), and monthly stats. All notifications are sent by enqueueing
  a normal `store.Email` through the same delivery pipeline (`Notifier.enqueue`), which
  fail-safe skips (no error) if the system domain isn't verified, and never queues about the
  permanent failure of a notification itself (`IsSystem` loop guard in `PermanentFailure`).
- **`internal/config`** — all configuration is env vars read once at startup; five are
  required and missing any of them is a hard exit (see README's Configuration table for the
  full list and defaults).

`cmd/seed-demo` is a standalone dev tool (not part of the shipped image) that seeds a scratch
SQLite DB with fake domains/keys/emails for taking admin UI screenshots.

## Conventions worth knowing before editing

- Money-quote invariants live in comments near the code they constrain (retry/timeout budgets
  in `delivery/worker.go` and `delivery/sender.go`, indeterminate-DNS handling in `dnscheck.go`
  /`main.go`/`admin.go`, the idempotency race in `api.go`). Read the existing comment before
  changing a related constant or control-flow branch — they usually explain a non-obvious
  reason a value is what it is.
- Fail-closed vs fail-open is deliberate per case: sending is fail-closed on unverified domains
  (403) and on indeterminate DNS checks (skip persisting, keep prior state); notifications are
  fail-open/fail-safe (skip silently if the system domain isn't verified, never blocking the
  underlying operation like key creation).
- From/To addresses are parsed with `net/mail.ParseAddress` and only the bare address is
  stored/used — a display name (`"Name <addr>"`) is currently silently stripped (documented
  v1 limitation in the README, not a bug to "fix" incidentally).
- Every `POST /api/v1/emails` validation happens before the domain/DKIM/queue lookups it's
  cheaper to fail fast on, and specifically before anything that would leave a permanently
  unsendable email sitting in the queue.
