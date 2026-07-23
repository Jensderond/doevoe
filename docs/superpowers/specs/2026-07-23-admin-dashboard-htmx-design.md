# Admin UI: no-flash navigation + dashboard graphs

Date: 2026-07-23
Status: Approved (design)

## Goal

Make the server-rendered admin UI feel responsive — navigate and filter without
full-page reloads ("screen flashes") — and add a statistics dashboard with graphs
(volume over time, delivery success, volume by domain, top failure reasons).

## Constraints (non-negotiable)

doevoe is a **single self-contained Go binary**: `html/template` server-rendered
pages, static assets embedded via `//go:embed`, SQLite only, CI is `go vet` +
`go test` + Docker build. This work MUST preserve that: **no Node, no npm, no
bundler, no JS build step.** CI stays unchanged.

## Approach

Two additions, both buildless:

1. **htmx** — one vendored minified file (~15KB) added to
   `internal/admin/static/` and embedded via the existing `//go:embed`. It
   intercepts nav clicks and form submits, fetches the page, and swaps only the
   `<main>` region in place — no full reload, no flash.
2. **`internal/svgchart`** — a new small, pure Go package that renders numbers to
   SVG strings. No JS, no external chart library. Charts reference the existing
   CSS color tokens so light/dark mode works automatically, and use
   `viewBox` + `width:100%` to be responsive.

The delivery pipeline, store schema, and public JSON API are **not** touched.

## Components

### 1. htmx navigation contract (`internal/admin`)

- `templates/layout.html`: `<main class="container">` gains `id="content"`. The
  nav and the filter/retry forms get `hx-boost` (or equivalent `hx-get`/`hx-post`
  with `hx-target="#content"`, `hx-push-url="true"`). The vendored
  `htmx.min.js` is loaded via `<script src="/admin/static/htmx.min.js">`.
- `admin.go` `render`/`renderStatus`: inspect the `HX-Request` request header. If
  present, execute **only** the `content` template (a fragment). Otherwise execute
  the full `layout`. htmx swaps `#content` innerHTML and pushes the URL, so back
  button and bookmarks keep working.
- **Progressive enhancement:** with JS disabled or htmx missing, every link/form
  is a plain `<a>`/`<form>` and full-page navigation behaves exactly as it does
  today. htmx `hx-boost` is additive, not required.
- **Auth-expiry edge case:** the `auth` middleware, when a request is
  unauthenticated *and* carries the `HX-Request` header, responds with an
  `HX-Redirect: /admin/login` header (HTTP 200, empty body) so the browser does a
  **full** redirect to the login page — rather than swapping the login form into
  the authed dashboard shell. Non-htmx requests keep the existing 303 redirect.

### 2. Stats queries (`internal/store`)

Add range-based (`[from, to)`, RFC3339 strings) query methods. Day bucketing uses
`substr(created_at, 1, 10)` (the `YYYY-MM-DD` prefix), consistent with the existing
UTC handling in `admin.parseFilterDate`. Buckets are keyed on `created_at` (when the
email entered the system), split by current `status`.

- `DailyVolume(from, to string) ([]DayCount, error)` — per-day `{Date, Sent, Failed}`.
- `SummaryStats(from, to string) (Summary, error)` — `{Sent, Failed, Queued, Total, SuccessRate}`.
  `Queued` counts `status IN ('queued','sending')`. `SuccessRate` guards against
  divide-by-zero when `Total == 0` (reports 0).
- `DomainVolume(from, to string) ([]DomainStats, error)` — per-domain sent/failed;
  a range-based sibling of the existing `MonthlyStats`.
- `FailureReasons(from, to string, limit int) ([]ReasonCount, error)` — range-based
  sibling of the existing `TopFailureReasons`.

To avoid duplication without disturbing the notifier's invariants, refactor the
existing month-prefix `MonthlyStats` and `TopFailureReasons` into **thin wrappers**
that compute the month's `[from, to)` boundaries and delegate to the new range
methods. Their signatures and call sites in `internal/notify` stay identical.

### 3. SVG chart rendering (`internal/svgchart`)

A new pure package. Input = numbers, output = `template.HTML` SVG string. No deps.

- `StackedBars(...)` — daily volume, sent (green) stacked with failed (red).
- `HBars(...)` — horizontal bars for volume-by-domain and failure reasons.
- Colors use the CSS custom properties already defined in `doevoe.css`
  (`var(--green)`, `var(--red)`, `var(--blue)`, `var(--muted)`, `var(--line)`),
  so charts follow the light/dark theme with no extra code.
- Responsive: fixed `viewBox`, `width:100%`, `height:auto`.
- Accessibility: chart `<svg>` carries a `role="img"` and an `<title>`/`aria-label`
  summarizing the data. Follows the project's `dataviz` guidance
  (accessible, consistent light/dark, existing palette tokens).
- **Empty data:** every chart function renders a friendly "No data for this range"
  placeholder rather than a blank or malformed SVG, and never divides by zero when
  computing bar scales.

### 4. Dashboard page (`internal/admin`)

- New nav item **"Overview"** in `layout.html`; `navSection` gains
  `"dashboard": "dashboard"`.
- `GET /admin/{$}` becomes the dashboard handler (today it redirects to
  `/admin/emails`). Route registered in `Routes`.
- Handler `dashboard(w, r)`: reads `?range=` clamped to `{7, 30, 90}` days
  (default 30, anything else falls back to 30), computes the `[from, to)` window in
  UTC, runs the four store queries, renders SVGs via `svgchart`, and renders
  `templates/dashboard.html`.
- Layout of `dashboard.html`:
  - **KPI row** — sent / success % / failed / queued for the range.
  - **Volume over time** — `StackedBars` (sent green, failed red).
  - **Volume by domain** — `HBars`.
  - **Top failure reasons** — `HBars`.
- The 7/30/90 range toggle uses htmx (`hx-get="/admin?range=7"`,
  `hx-target="#content"`, `hx-push-url="true"`) — instant swap, no reload.

## Error handling & edge cases

- Empty range → "No data for this range" in each chart; KPIs show zeros.
- `SuccessRate` divide-by-zero guard when `Total == 0`.
- `range` param outside `{7,30,90}` → default 30.
- Session expiry during an htmx request → `HX-Redirect` full-page redirect to login.
- All date bucketing in UTC, matching existing store/admin conventions.

## Testing

- **`internal/store`**: seed emails across several days, domains, and statuses;
  assert `DailyVolume`/`SummaryStats`/`DomainVolume`/`FailureReasons` bucket counts;
  assert the refactored `MonthlyStats`/`TopFailureReasons` wrappers still return the
  same results as before.
- **`internal/svgchart`**: assert SVG output contains the expected number of bars,
  labels, and dimensions; assert empty input renders the placeholder and never
  panics or divides by zero.
- **`internal/admin`**: dashboard route returns 200 and contains the KPI values; a
  request with the `HX-Request` header returns a fragment with no `<html>`/`<body>`;
  an expired session on an htmx request returns `HX-Redirect` to `/admin/login`.

## Out of scope (YAGNI)

- No Alpine.js — htmx alone covers no-flash navigation and range swaps.
- No websockets / auto-refresh polling.
- No CSV export.
- No custom free-form date-range picker on the dashboard (only 7/30/90 presets).

## Decisions made during brainstorming

- Buildless htmx + Alpine-style approach chosen over a full React SPA (preserves
  single-binary, zero-build-step model).
- Server-rendered SVG in Go chosen over a vendored JS chart library (purest fit,
  fully unit-testable; trade-off is no hover tooltips).
- All four graphs included: volume over time, delivery success, volume by domain,
  top failure reasons.
- "Overview" becomes the landing page; 7/30/90 presets rather than a date picker.
