# Emails list & monthly stats improvements — design

Date: 2026-07-21
Scope: three v1 scope cuts from README "v1 scope notes", now being implemented:
date-range filter, monthly stats month-over-month comparison, pagination UI.

## 1. Date-range filter in the admin emails list

**What:** two `<input type="date">` fields (`from`, `to`) in the existing
filter form on `/admin/emails`, filtering on `created_at`.

**Why created_at (not sent_at):** the list is sorted by `created_at` and
displays it on every card; `sent_at` is empty for queued/failed mail, so a
sent-date filter would silently hide everything that never sent. One
unambiguous field beats a mode switch.

**Store:** `EmailFilter` gains `CreatedFrom, CreatedTo string` (RFC3339
timestamps). `ListEmails` appends `created_at >= ?` / `created_at < ?`.
Timestamps are stored as RFC3339 UTC strings, so string comparison is
correct and uses the existing ordering.

**Handler:** parses `from`/`to` query params as `2006-01-02` dates (UTC).
`from` maps to `fromT00:00:00Z`; `to` maps to *the next day* `T00:00:00Z`
with a `<` comparison, so the "to" day is inclusive, matching what a date
picker means to a human. Unparseable values are ignored (treated as unset)
rather than erroring — same forgiving posture as the other filters
(`strconv.ParseInt(..)` on `domain` already ignores errors).

## 2. Month-over-month comparison in the monthly stats email

**What:** the monthly digest for month M additionally loads
`MonthlyStats(M-1)` and appends a comparison to each per-domain line, plus
a delta on the delivery rate:

```
- example.com: 120 sent, 3 failed (97.6% delivered) — prev month: 110 sent, 5 failed (95.7%), +1.9pt
```

Domains with activity in M but none in M-1 get `— prev month: no activity`.
Domains active in M-1 but silent in M get their own line:
`- example.com: no activity — prev month: 110 sent, 5 failed (95.7%)`,
so a domain going quiet is visible instead of vanishing from the report.

**Failure mode:** if the previous-month lookup errors, log a warning and
send the report without comparisons (fail-open, consistent with how
`TopFailureReasons`/`ListDomains` errors are already handled in
`StatsTick`).

No schema or state changes: `MonthlyStats` is already parameterized by
month prefix; we just call it twice.

## 3. Pagination UI for the emails list

**What:** `page` query param (1-based, default 1), fixed page size 50.
The handler requests `Limit: pageSize+1` to detect whether a next page
exists, renders at most 50, and the template shows "← Newer / Older →"
links plus "Page N" when there is anything to paginate. All active filters
(status, domain, q, from, to) are preserved in the links.

**Why limit+1 instead of COUNT(*):** avoids a second query and a total
count nobody asked for; the UI only needs "is there more". Invalid or
sub-1 `page` values fall back to page 1.

No store changes: `ListEmails` already supports `Limit`/`Offset`.

## Testing

Following the existing table-less handler-test style in
`internal/admin/emails_test.go` (fixture server + substring assertions)
and store tests in `internal/store/emails_test.go`:

- store: `ListEmails` respects `CreatedFrom`/`CreatedTo`, combined with
  other filters.
- admin: date filter narrows results; inclusive "to" day; invalid dates
  ignored; pagination shows page 2 content, next/prev links preserve
  filters, out-of-range page renders empty state.
- notify: stats email contains prev-month comparison, handles
  no-prior-activity and domain-went-quiet cases; prev-month lookup error
  still sends the report.

README's "v1 scope notes" entries for these three items are removed.
