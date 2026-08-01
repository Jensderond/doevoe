# DMARC report ingestion + DNSBL blacklist monitoring

**Date:** 2026-08-01
**Status:** Phases 1 and 2 implemented
**Scope:** Early detection of deliverability problems: (1) hourly DNS-blacklist
checks for the egress IP and every verified domain, alerting on new listings;
(2) receiving, parsing, storing, and visualizing DMARC aggregate reports, with
an alert when our own mail fails DMARC. Built as two independently mergeable
phases, DNSBL first.

## Problem

doevoe delivers directly to recipient MX servers, so its deliverability depends
on two externally-observable signals it currently cannot see:

- **Blacklists.** If the egress IP or a sending domain lands on Spamhaus,
  SpamCop, Barracuda, DBL, or SURBL, recipient servers start rejecting or
  junk-foldering mail. Today the operator finds out from user complaints.
- **DMARC aggregate reports.** Every domain doevoe sets up publishes
  `rua=mailto:<adminEmail>` (`dkimkeys.Records`), so Google/Yahoo/Microsoft
  already send daily XML reports showing exactly how our mail authenticates —
  but they land unparsed in the admin's personal inbox. doevoe is send-only
  and has no way to receive them.

## Decisions already made (with the user)

- DMARC reports are received by a **built-in inbound SMTP listener** in the
  doevoe binary (no IMAP polling, no manual upload).
- Parsed reports get an **admin page and alerts** (alert only when our own
  egress IP fails DMARC; spoofing by other IPs is visible on the page but
  silent).
- The DNSBL zone set is **hardcoded** — no env override.
- One spec, two phases: **DNSBL ships first**, then the receiver.

## Phase 1: DNSBL monitoring

### New package `internal/dnsbl`

Mirrors `internal/dnscheck`'s shape: pure functions over an injected
`Resolver` interface so tests use a fake.

Hardcoded zones:

| Kind   | Zone                     | Listed answer      |
|--------|--------------------------|--------------------|
| IP     | `zen.spamhaus.org`       | `127.0.0.2–11`     |
| IP     | `bl.spamcop.net`         | `127.0.0.2`        |
| IP     | `b.barracudacentral.org` | `127.0.0.2`        |
| Domain | `dbl.spamhaus.org`       | `127.0.1.x`        |
| Domain | `multi.surbl.org`        | `127.0.0.x`        |

`Check(ctx, resolver, egressIP, domains) []Status` queries
`<reversed-ip>.<zone>` (A lookup) for IP zones and `<domain>.<zone>` for
domain zones. Each `Status{Target, Zone, Verdict}` has verdict:

- **NotListed** — NXDOMAIN (the normal, healthy answer).
- **Listed** — an answer in the zone's documented listed range above.
- **Indeterminate** — anything else: timeouts, SERVFAIL, and critically the
  Spamhaus error codes `127.255.255.x` ("public resolver / rate limited /
  blocked", used by both ZEN and DBL). **Indeterminate results are
  never persisted and never alerted** — same money-quote invariant as
  `dnscheck.Result.Indeterminate`. Without this, any install using
  Google/Cloudflare DNS gets permanent false "you're blacklisted" alerts,
  because Spamhaus refuses public resolvers by design.

### Storage: `blocklist_status` table (`internal/store/blocklist.go`)

```
blocklist_status(target TEXT, zone TEXT, listed INTEGER,
                 since TEXT, last_checked TEXT, PRIMARY KEY(target, zone))
blocklist_events(id INTEGER PK, target TEXT, zone TEXT, listed INTEGER,
                 occurred_at TEXT)
```

New tables only — `CREATE TABLE IF NOT EXISTS` in the schema constant
suffices, no `migrate()` step needed. `RecordBlocklistCheck` persists a
determinate result and returns the transition it caused ("listed",
"cleared", or "" for steady state) so the caller can detect transitions;
`ListBlocklistStatus` feeds the dashboard's current-status view, and
`RecentBlocklistEvents` feeds its history view.

`blocklist_events` is the append-only history: one row per **transition**
(listed / cleared), written in the same transaction as the status upsert.
Transitions — not hourly snapshots — are the stored grain: snapshots would be
thousands of redundant "still clear" rows per month, while transitions plus
`last_checked` reconstruct the full timeline losslessly. They're rare enough
to keep indefinitely (no retention), so the dashboard can answer "have we
ever been listed, when, and for how long" without any live lookup.

### Loop + alerting

A new `blocklistLoop` in `cmd/doevoe/main.go`, sibling of `recheckDNSLoop`,
hourly ticker, checking `cfg.EgressIP` plus every **verified** domain
(unverified domains can't send, so their listing status is noise). On a
determinate verdict it upserts; on a transition it calls:

- not-listed → listed: `notifier.BlocklistHit(target, zone)`
- listed → not-listed: `notifier.BlocklistCleared(target, zone)`

Both are fire-and-forget `notifier.enqueue` wrappers like `KeyCreated` —
fail-open if the system domain isn't verified. **The stored previous state is
the arm/re-arm mechanism**: one email per transition, no `notify_state`
cooldown needed, because the upsert only reports a transition once.

### Admin UI

Dashboard gets a small block: "Blacklists: all clear (last checked …)" or a
table of active listings (target, zone, since), plus the most recent
`blocklist_events` rows (e.g. last 10) so past listings and their clear
times stay visible after recovery. No new page.

## Phase 2: DMARC report ingestion

### 2a. Inbound SMTP receiver — new package `internal/inbound`

Uses `github.com/emersion/go-smtp`'s **server** (already a dependency for the
client side; zero new deps). Config: `DOEVOE_INBOUND_LISTEN`, default `:25`,
empty string disables the listener entirely.

This is deliberately *not* a mail server:

- At RCPT time it rejects (550) every recipient except exactly
  `dmarc@<system-domain>`, where system-domain is the domain of
  `cfg.SystemFrom`. It never relays, receives no user mail, and needs no auth.
- Hard message size cap (15 MB), go-smtp read/write timeouts, and per-message
  panic recovery (same rationale as the worker's per-email recovery).
- No STARTTLS in v1. Reporting senders fall back to plaintext delivery when
  STARTTLS is unavailable, which is acceptable for reports *about* us.
  Follow-up noted below.
- A **malformed, oversized-after-decompression, or duplicate report is
  accepted at the SMTP level (250) and logged, never 5xx'd** — rejecting only
  makes the reporter retry a message we will never parse. Fail-open.

The handler pipeline: MIME-walk the message for the first part whose
content-type/filename indicates `gzip`, `zip`, or bare `xml`; decompress with
a hard 50 MB output cap (`io.LimitReader` — decompression-bomb guard); hand
the XML to `internal/dmarcreport`; insert via the store.

### 2b. Parser — new package `internal/dmarcreport`

Stdlib `encoding/xml` structs for the RFC 7489 Appendix C aggregate report:
report metadata (org name, email, report ID, date range), policy published,
and per-record rows (source IP, count, disposition, DKIM/SPF policy-evaluated
results, header-from). `Parse(r io.Reader) (*Report, error)`. Pure, no store
dependency.

### 2c. Storage: two tables (`internal/store/dmarc.go`)

```
dmarc_reports(id INTEGER PK, org TEXT, report_id TEXT, domain TEXT,
              range_begin TEXT, range_end TEXT, received_at TEXT, raw TEXT,
              UNIQUE(org, report_id))
dmarc_records(id INTEGER PK, report_id INTEGER REFERENCES dmarc_reports(id),
              source_ip TEXT, count INTEGER, disposition TEXT,
              dkim TEXT, spf TEXT, header_from TEXT)
```

- `UNIQUE(org, report_id)` dedups reporter re-sends; a constraint hit is the
  duplicate case above (log, accept, drop).
- `raw` keeps the decompressed XML for debugging parse gaps; retention prunes
  reports (and their records) older than 90 days, run from `blocklistLoop`'s
  hourly tick.
- Insert of report + records is one transaction.

### 2d. DNS setup surface

- `dkimkeys.Records` changes the recommended DMARC record for **every** domain
  to `rua=mailto:dmarc@<system-domain>`.
- The admin UI shows two extra one-time records for the **system domain**:
  - `MX` → `cfg.Hostname` (so reporters can deliver to us).
  - `*._report._dmarc.<system-domain>` TXT `v=DMARC1` — RFC 7489 §7.1
    external destination verification, required for other domains to point
    their `rua` at the system domain. Wildcard covers all current and future
    domains.
- `dnscheck`'s DMARC check only asserts a `v=DMARC1` prefix, so already-
  verified domains with the old `rua` stay verified. No behavior change there.

### 2e. Admin page `/admin/dmarc`

One page, date-bounded via the same `emailWindow`/`resolveEmailWindow`
pattern as the email list (period chips, custom range): per-domain rollup
(pass/fail message counts), top failing source IPs, and the report list
(org, domain, range, record count). No per-report detail page in v1 — the
rollup plus the raw column cover investigation.

### 2f. Alert: our own mail failing DMARC

After storing a report, if any record has `source_ip == cfg.EgressIP` and a
failing DMARC evaluation (both DKIM and SPF results fail), call
`notifier.DMARCFailure(domain, count)`. Cooldown: at most one alert per
domain per 24 h via the existing `notify_state` key mechanism (like
`RateTick`'s arm/re-arm). This is the "our signing/DNS broke" early-warning;
other-IP failures (spoofing) stay page-only by design.

## Wiring (`cmd/doevoe/main.go`)

Phase 1 adds `blocklistLoop(ctx, s, notifier, cfg.EgressIP)`. Phase 2 adds the
inbound server goroutine (started only when `DOEVOE_INBOUND_LISTEN` is
non-empty), shut down via the same signal context, and joins the existing
`sync.WaitGroup` before `store.Close`.

## Error handling summary

| Failure | Behavior |
|---|---|
| DNSBL timeout / SERVFAIL / Spamhaus public-resolver code | Indeterminate: skip persist + alert |
| System domain unverified | Alerts silently skipped (existing `enqueue` fail-open) |
| Malformed / bomb / duplicate DMARC report | SMTP 250, log, drop |
| RCPT to anything but the report address | SMTP 550 |
| Inbound listener fails to bind | Startup error + exit (misconfiguration, same as other config errors) — unless disabled by empty listen addr |

## Testing

- `dnsbl`: fake-resolver table tests — listed codes per zone, NXDOMAIN,
  Spamhaus `127.255.255.x` → Indeterminate, timeout → Indeterminate.
- `dmarcreport`: fixture reports shaped like real Google/Yahoo output (gzip,
  zip, bare XML; multi-record; missing optional fields).
- `inbound`: end-to-end test — go-smtp client delivers a gzipped fixture to
  the listener on a random port, assert rows in a temp store; RCPT rejection;
  oversize rejection; malformed report accepted-and-dropped.
- `store`: upsert transition semantics for `blocklist_status` including the
  transactional `blocklist_events` append (event written on transition, none
  on steady state); dedup constraint and transactional insert for DMARC
  tables; retention pruning.
- `notify`: the three new notification methods, mirroring existing tests.

## Out of scope / follow-ups

- STARTTLS on the inbound listener (needs cert management).
- DMARC forensic (`ruf`) reports — rarely sent by major providers.
- Per-report detail page in the admin UI.
- Auto-remediation or delisting requests for blacklist hits.
