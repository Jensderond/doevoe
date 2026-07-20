# Doevoe — Self-hosted transactional email API

**Date:** 2026-07-20
**Status:** Approved design

## Purpose

Doevoe is a small, self-hosted transactional email service for agency use: one
deployment sends signed email for many client sites (Next.js apps, SPAs with a
backend, CMS installs). It owns delivery end-to-end — DKIM signing,
direct-to-MX SMTP, retries — and gives an admin a log view where failed emails
can be inspected, edited (e.g. fix a typo'd recipient domain), and retried.
It tells the operator exactly which DNS records each sending domain needs
(SPF, DKIM, DMARC) and verifies them live.

## Constraints & key decisions

| Decision | Choice | Rationale |
|---|---|---|
| Delivery model | Own MTA, direct-to-MX | Fully self-contained; DNS records are genuinely ours. Operator owns IP reputation (PTR + clean IP required). |
| Client auth | Server-side secret keys only | Keys live in Next.js API routes / backends, never in browser JS. No browser-callable keys in v1. |
| Tenancy | Multi-domain, one deployment | One instance hosts many sending domains, each with own DKIM keys, verification status, API keys. |
| Language | Go | Mature ecosystem (`emersion/go-smtp`, `emersion/go-msgauth`); single static binary; ~30–50MB RSS. |
| Storage | SQLite (WAL, `modernc.org/sqlite`, no CGO) | One file is queue + log + config. Admin log view needs indexed queries a KV store would make painful. |
| Deployment | Docker Compose, single service + named volume | ~15MB image. Reverse proxy / TLS left to host or optional Caddy service. |
| Non-goals (v1) | Templates, batch sending, webhooks, inbound bounce (DSN) parsing, multi-node HA, browser-callable public keys | YAGNI; storage layer behind an interface keeps a Postgres migration path open. |

## 1. Architecture

One Go binary, four components sharing one SQLite database:

- **HTTP API** (stdlib `net/http`): `/api/v1/*` endpoints called by client backends with secret keys.
- **Delivery engine**: worker pool that claims due messages from SQLite, resolves recipient MX records, DKIM-signs, delivers over SMTP with STARTTLS.
- **DNS wizard**: generates DKIM keys per domain; live-verifies SPF/DKIM/DMARC via DNS lookups; hourly recheck.
- **Admin UI**: server-rendered `html/template` pages embedded via `embed.FS`; session-cookie login. No JS framework, no build step.

All coordination goes through the database: a crash or redeploy loses nothing; queued mail resumes.

## 2. Data model

- **domains** — name, DKIM selector, DKIM private key, per-record verification status (SPF / DKIM / DMARC), last-checked timestamp.
- **api_keys** — name, SHA-256 hash of key (plaintext shown once at creation), allowed sending domain(s), revoked flag, last-used timestamp.
- **emails** — from, to, subject, HTML/text bodies, custom headers, `status` (`queued` → `sending` → `sent` | `failed`), `attempts`, `next_attempt_at`, `last_error`, `original_to` (audit trail for admin recipient edits), idempotency key, timestamps. This table is both the queue and the log.
- **delivery_attempts** — one row per SMTP attempt: MX host tried, SMTP status code, server response text, duration, timestamp.
- **notifications state** — digest accumulation, per-domain alert armed/fired state, `last_stats_sent` marker (see §9).

Indexes support the admin queries: by status, by domain, by recipient (search), by date.

## 3. API surface

- `POST /api/v1/emails` — `Authorization: Bearer <secret>`. Body: `from` (must be on the key's allowed domain), `to`, `subject`, `html` and/or `text`, optional `reply_to`, `headers`. Optional `Idempotency-Key` header: a retried client request returns the original message instead of double-sending. Returns `202 {id, status: "queued"}` — delivery is always async.
- `GET /api/v1/emails/{id}` — status + attempt summary for polling.

Sending from an unverified domain is refused with an explanatory error (**fail closed** — unsigned mail would poison IP reputation).

## 4. Delivery & retry engine

- Workers claim due messages atomically (`UPDATE … SET status='sending' WHERE id IN (SELECT … WHERE next_attempt_at <= now LIMIT n)`) — no double-sends with concurrent workers.
- **DKIM signing happens at send time**, not enqueue time: an admin recipient edit changes the `To:` header, which is part of the signature.
- MX hosts tried in preference order; STARTTLS used when offered.
- Error classification:
  - SMTP 4xx / network errors → retry with backoff **1m, 5m, 15m, 1h, 4h, 12h, 24h**, then permanently failed (~48h total, matching conventional MTA behavior).
  - SMTP 5xx → immediate permanent failure. No automatic retry; admin manual retry covers it.
- Politeness: per-recipient-domain concurrency cap (2 connections) so bursts to one provider don't look like spam.

## 5. DNS wizard

Adding a domain generates an RSA-2048 DKIM keypair (selector e.g. `mail1`) and shows a copy-pasteable checklist:

| Record | Host | Value |
|---|---|---|
| TXT (SPF) | `@` | `v=spf1 ip4:<egress-ip> -all` |
| TXT (DKIM) | `mail1._domainkey` | `v=DKIM1; k=rsa; p=MIIB…` |
| TXT (DMARC) | `_dmarc` | `v=DMARC1; p=quarantine; rua=mailto:…` |

Plus a non-verifiable checklist item the UI nags about: a **PTR (reverse DNS) record** on the egress IP matching the `EHLO` hostname — without it, Gmail/Outlook junk or refuse mail regardless of DKIM.

A **Verify** button does live lookups, marking each record ✓/✗ with found-vs-expected values. A background job rechecks hourly. Verification state gates sending (§3).

## 6. Admin UI

The admin UI is **mobile-first**: layouts are designed for phone screens first (single-column cards, large touch targets, no horizontal scrolling), then enhanced at larger breakpoints with `min-width` media queries (e.g. list views become tables on desktop). Server-rendered HTML, no JS framework.

- **Login** — single admin account; password from env var at first boot; session cookie.
- **Emails** — filterable list (status, domain, recipient search, date range); detail page with full attempt history and SMTP transcripts. Failed emails offer:
  - **Retry now** — re-queues as-is.
  - **Edit recipient → retry** — fix a typo'd address/domain (`gmial.com` → `gmail.com`); original preserved in `original_to` and shown struck-through.
- **Domains** — the DNS wizard (§5) with per-record status.
- **API keys** — create (plaintext shown once), revoke.

## 7. Deployment & ops

```yaml
services:
  doevoe:
    image: <registry>/doevoe
    ports: ["8080:8080"]
    volumes: ["data:/data"]
    environment:
      DOEVOE_HOSTNAME: mail.example.com     # EHLO name, must match PTR
      DOEVOE_ADMIN_PASSWORD: ...
      DOEVOE_ADMIN_EMAIL: you@example.com   # notification recipient
      DOEVOE_SYSTEM_FROM: noreply@mail.example.com
volumes:
  data:
```

Hard operational requirements, stated up front in README and setup checklist (no code can work around them):

1. **Outbound port 25** — most clouds block by default (Hetzner/OVH allow on request; AWS/GCP mostly don't).
2. **Static egress IP with an operator-controlled PTR record** matching `DOEVOE_HOSTNAME`.

TLS for the API/admin itself is delegated to an existing reverse proxy, or an optional Caddy service in the compose file. Backups = copying the SQLite file (Litestream optional, out of scope for v1).

## 8. Testing

- **Unit**: backoff math, SMTP error classification, DKIM signing (round-trip verify with the same library), DNS record generation.
- **Integration**: in-process throwaway SMTP server asserting full delivery, retry-after-4xx, permanent-fail-after-5xx, idempotency, and admin edit-recipient→retry flows.
- **DNS wizard**: stubbed resolver covering verified / missing / wrong-value records.

TDD throughout.

## 9. Admin notifications & monthly stats

A **notifier** component enqueues emails to `DOEVOE_ADMIN_EMAIL` from `DOEVOE_SYSTEM_FROM` (must be on a verified domain; setup checklist enforces this). Notifications ride the normal queue — signed, retried, logged like any other mail.

- **Permanent failure digest** — when emails exhaust retries or hard-bounce: digest listing each failure (recipient, subject, error, admin deep-link). Hourly cooldown batching: first failure after a quiet period sends within a minute; the rest accumulate into the next digest. An outage produces one email, not hundreds.
- **Elevated failure rate** — configurable threshold: >N% of delivery attempts failed for a domain in the last hour, with a minimum-volume floor (so 1-of-2 failing doesn't alert). Fires immediately, once per domain per incident; re-arms when the rate drops below threshold.
- **API key lifecycle** — immediate notification on key creation or revocation, naming key and domain.
- **Monthly stats email** — on the first of each month: per-domain sent/failed/delivery-rate table, previous-month comparison, top failure reasons, DNS verification status. Driven by a `last_stats_sent` DB marker, not cron — downtime on the 1st doesn't skip a month.

Fail-safe edge case: if a notification email itself can't be delivered, it sits in the queue retrying and stays visible in the admin; the notifier never alerts about its own failures (no loops).

**Deliberately excluded:** DNS-regression alerts. A failed recheck blocks sending at the API, so a regression surfaces as client-app API errors and on the admin domains page. One-line event to add later if it bites.
