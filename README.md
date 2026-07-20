# doevoe

doevoe is a self-hosted transactional email API: point your app at it and it
queues, signs (DKIM), delivers, and retries mail directly to recipient MX
servers — no third-party ESP, no per-email fee. It ships as a single Go
binary with an embedded SQLite store, a JSON send/status API, and a
mobile-friendly admin UI for domain setup, API keys, and delivery logs.

## Hard requirements

Before you deploy, make sure the host you're using can actually send mail:

- **Outbound TCP port 25 must be open.** doevoe delivers straight to
  recipients' MX servers over SMTP — there is no smarthost/relay fallback.
  Most consumer clouds block outbound port 25 by default:
  - Hetzner, OVH and most classic VPS/dedicated providers allow it, sometimes
    after a support-ticket request to unblock it.
  - AWS, GCP and Azure block it by default and require a formal request to
    lift the block (AWS: "Remove email sending limitations" support case; GCP
    largely does not support outbound 25 on standard instances). Budget time
    for this before you commit to a provider.
- **A static egress IP with a PTR record you control.** doevoe's generated
  SPF record pins to a single IP (`DOEVOE_EGRESS_IP`), and Gmail/Outlook/etc.
  will junk or reject mail from an IP whose reverse DNS (PTR) doesn't resolve
  back to `DOEVOE_HOSTNAME`. Set the PTR record with your hosting provider
  (not in the sending domain's own DNS) before sending real traffic.
- **Put a TLS-terminating reverse proxy in front of it.** doevoe's `/admin`
  and `/api` listen on plain HTTP (`DOEVOE_LISTEN`, default `:8080`) and the
  admin session cookie is **not** marked `Secure`. Never expose port 8080
  directly to the internet — put Caddy, nginx, or Traefik in front of it
  terminating TLS, and only forward to doevoe over localhost/a private
  network.

## Quickstart

```bash
git clone <this repo> && cd doevoe
cp .env.example .env
# edit .env: hostname, egress IP, admin password/email, system from-address
docker compose up -d
```

Then:

1. Open `https://your-proxy/admin` (behind your reverse proxy) and log in
   with `DOEVOE_ADMIN_PASSWORD`.
2. Add a domain (e.g. `client.example`). doevoe generates a DKIM keypair for
   it and shows you the exact SPF, DKIM, DMARC, and PTR records to add at
   your DNS provider.
3. Add those DNS records, then click **Verify** on the domain page (doevoe
   also re-checks every domain automatically once an hour).
4. Once SPF/DKIM/DMARC all show verified, create an API key scoped to that
   domain under **Keys**. The plaintext token is shown exactly once — copy
   it now.
5. Use the key to send:

```bash
curl -s https://your-proxy/api/v1/emails \
  -H "Authorization: Bearer $DOEVOE_API_KEY" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $(uuidgen)" \
  -d '{"from":"hello@client.example","to":"someone@gmail.com","subject":"Hi","text":"Hello!"}'
```

### API usage from Next.js

Keep the API key server-side — never ship it to the browser. A typical
route handler:

```ts
// app/api/contact/route.ts — the secret key stays server-side
export async function POST(req: Request) {
  const { email } = await req.json();
  const res = await fetch("https://doevoe.example.com/api/v1/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${process.env.DOEVOE_API_KEY}`,
      "Content-Type": "application/json",
      "Idempotency-Key": crypto.randomUUID(),
    },
    body: JSON.stringify({
      from: "hello@client.example",
      to: email,
      subject: "Thanks for reaching out",
      text: "We got your message and will reply soon.",
    }),
  });
  return Response.json(await res.json(), { status: res.status });
}
```

`Idempotency-Key` is optional but recommended: resending the same key
returns the original queued/sent result instead of sending a duplicate
email, which makes retries on the caller's side safe.

Both `from` and `to` are parsed as a single RFC 5322 address
(`mail.ParseAddress`) and only the bare address is stored and used — a
display name in the `"Name <addr>"` form is accepted but currently
**silently stripped**: doevoe sends (and shows in the admin UI) just
`addr`, never `Name <addr>`. If you need the recipient/sender name to show
up in the mail client's From/To header, put it together with the address
yourself on the caller's side before the display-name support lands, or
track that as a known v1 limitation (see below).

## Configuration

All configuration is environment variables, read once at startup
(`internal/config`). The five marked **required** must be set or doevoe
exits immediately with an error.

| Variable | Required | Default | Meaning |
|---|---|---|---|
| `DOEVOE_HOSTNAME` | yes | — | EHLO hostname; must match the PTR record for `DOEVOE_EGRESS_IP` |
| `DOEVOE_EGRESS_IP` | yes | — | Public IPv4 this host sends from; baked into the generated SPF record and checked against the PTR |
| `DOEVOE_ADMIN_PASSWORD` | yes | — | Password for the single `/admin` account |
| `DOEVOE_ADMIN_EMAIL` | yes | — | Recipient for failure digests, rate alerts, monthly stats, key lifecycle notices, and the DMARC `rua` address |
| `DOEVOE_SYSTEM_FROM` | yes | — | From-address doevoe uses for its own notifications; its domain must be one of the domains verified in doevoe |
| `DOEVOE_PUBLIC_URL` | no | `http://$DOEVOE_HOSTNAME` | Public base URL (e.g. `https://mail.example.com`, no trailing slash) used to build the deep links in doevoe's own notification emails; set this to your reverse proxy's HTTPS address, since the default is plain HTTP and won't match it |
| `DOEVOE_LISTEN` | no | `:8080` | HTTP listen address for the API + admin UI |
| `DOEVOE_DATA_DIR` | no | `/data` | Directory for the SQLite database (`doevoe.db`) |
| `DOEVOE_SMTP_PORT` | no | `25` | Outbound SMTP port used to connect to recipient MX servers |
| `DOEVOE_FAILURE_RATE_MIN_VOLUME` | no | `10` | Minimum delivery attempts in the trailing hour before the failure-rate alert can fire for a domain |
| `DOEVOE_FAILURE_RATE_THRESHOLD` | no | `0.2` | Failure ratio (0–1) over the trailing hour that triggers the failure-rate alert |

## Delivery and retries

Emails are delivered directly to the recipient's MX servers (with an
RFC 5321 fallback to the A record if there's no MX). A 5xx (permanent) SMTP
response fails the email immediately; anything else (4xx, timeouts,
connection errors) is retried on a fixed backoff schedule, in order:

`1m → 5m → 15m → 1h → 4h → 12h → 24h`

After the 24-hour attempt fails, the email is marked permanently failed and
no further attempts are made — retry manually from `/admin/emails/{id}` if
appropriate (optionally editing the recipient address first).

## Notifications

doevoe emails `DOEVOE_ADMIN_EMAIL` (from `DOEVOE_SYSTEM_FROM`, itself queued
through the normal delivery pipeline — so the system domain must be
verified for notifications to actually go out) in these cases:

- **Failure digest** — batches every email that permanently failed since the
  last digest into one message, with links to `/admin/emails/{id}`. Sent at
  most once per hour (a cooldown, not a fixed schedule): it fires on the
  first check after an hour has passed since the last digest, but only if
  there's something new to report.
- **Elevated failure-rate alert** — per domain, if at least
  `DOEVOE_FAILURE_RATE_MIN_VOLUME` delivery attempts happened in the
  trailing hour and the failure ratio is at or above
  `DOEVOE_FAILURE_RATE_THRESHOLD`, sends one alert (not repeated every
  check) and re-arms once the rate drops back below threshold.
- **API key created / revoked** — one email per key lifecycle event.
- **Monthly stats** — on the first check of a new calendar month, a summary
  of the previous month: sent/failed counts and delivery rate per domain,
  top failure reasons, and current SPF/DKIM/DMARC verification status per
  domain. A fresh install does not get a phantom report for its
  (incomplete) install month.

All of the above run on a one-minute internal ticker; none of it blocks
sending.

## Backups

The database is a single SQLite file at `$DOEVOE_DATA_DIR/doevoe.db`,
opened in WAL mode. You can back it up without stopping doevoe:

```bash
# safe online backup, no downtime
sqlite3 /path/to/doevoe.db ".backup '/path/to/backup.db'"
```

A plain `cp` of the file while doevoe is running is not guaranteed
consistent (it can race with in-flight WAL writes) — use `.backup` (or stop
the container first) for anything you actually intend to restore from.

## Docker

```bash
docker build -t doevoe .
docker compose up -d      # reads .env for the required DOEVOE_* variables
```

The image is a static binary (`CGO_ENABLED=0`) on `distroless/static-debian12`
— no shell, no package manager, minimal attack surface. Data persists in the
`data` named volume mounted at `/data`.

## v1 scope notes

The following are deliberate cuts for this first version, not oversights —
listed here so they're a documented decision rather than a surprise:

- **No date-range filter in the admin emails list** — you can filter by
  status, domain, and a free-text search over recipient/subject, but not by
  a created/sent date range.
- **Monthly stats have no previous-month comparison** — the monthly digest
  reports the previous month's numbers in isolation, with no month-over-month
  delta or trend.
- **No pagination UI** — `ListEmails` supports `Limit`/`Offset`, but the
  admin emails list only ever renders the first page (default limit 50);
  there's no "next page" control yet.
- **No CSRF tokens** — admin form-post routes rely solely on the session
  cookie's `SameSite=Lax` attribute for CSRF protection, not an explicit
  per-form token.
- **The container runs as root** — the distroless image doesn't drop
  privileges to a non-root user; it relies on the container boundary and the
  lack of a shell/package manager in the image, not a `USER` directive, for
  isolation.
