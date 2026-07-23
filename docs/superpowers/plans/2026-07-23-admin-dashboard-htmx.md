# Admin no-flash UI + dashboard graphs — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the server-rendered admin UI navigate/filter without full-page reloads (htmx), and add an Overview dashboard with server-rendered charts (volume over time, delivery success, volume by domain, top failure reasons).

**Architecture:** Vendor one minified htmx file (embedded via the existing `//go:embed static/*`) and boost GET navigation so only the page shell is swapped in place — no flash, full progressive-enhancement fallback. Add a pure `internal/svgchart` package that turns numbers into SVG/HTML, and new range-based aggregate queries in `internal/store`. A new `dashboard` admin handler wires them into an `Overview` page with a 7/30/90-day range toggle.

**Tech Stack:** Go `html/template`, embedded assets, modernc.org/sqlite, htmx 2.0.4 (vendored static file). No Node/npm/bundler.

## Global Constraints

- No Node, npm, bundler, or JS build step. CI stays `go vet ./...` + `go test ./...`.
- htmx is a **vendored** file committed to the repo (`internal/admin/static/htmx.min.js`), never a CDN reference.
- All timestamps are RFC3339 UTC strings via `store.Now()`/`store.FmtTime()`; all date bucketing is UTC.
- Charts reference existing CSS color tokens (`var(--green)`, `--red`, `--blue`, `--inset`, `--muted`, `--ink`) so light/dark mode works with no extra code.
- Do not change the sending pipeline, public JSON API, or DB schema.
- Follow the existing "airmail ledger" design system in `internal/admin/static/doevoe.css`.

## File Structure

- `internal/admin/static/htmx.min.js` — **create** (vendored).
- `internal/admin/templates/layout.html` — **modify**: split into `layout` (full doc) + `shell` (topbar + main), add htmx boot + boost attributes.
- `internal/admin/admin.go` — **modify**: `render`/`renderStatus`/`renderKeys` take `*http.Request`; fragment vs full rendering; `auth` HX-Redirect; new `dashboard` handler + route; `navSection` gains `dashboard`.
- `internal/admin/templates/{login,email,domains,domain,keys}.html` — **modify**: add `hx-boost="false"` to POST forms.
- `internal/admin/templates/dashboard.html` — **create**.
- `internal/store/stats.go` — **create**: `DailyVolume`, `SummaryStats`, `DomainVolume`, `FailureReasons`, `monthRange`, `DayCount`, `Summary`.
- `internal/store/notify.go` — **modify**: `MonthlyStats`/`TopFailureReasons` become thin wrappers over the range methods.
- `internal/store/stats_test.go` — **create**.
- `internal/svgchart/svgchart.go` — **create**: `DayBar`, `HBar`, `StackedBars`, `HBars`.
- `internal/svgchart/svgchart_test.go` — **create**.
- `internal/admin/admin_test.go` — **modify**: add htmx/fragment/dashboard tests.
- `internal/admin/static/doevoe.css` — **modify**: append dashboard styles.

### Design refinements agreed vs the spec

- The htmx swap target is `#shell` (topbar + main), swapped `outerHTML`, so the nav active-underline updates on navigation. (The spec said `#content`; swapping the shell is required to refresh the active nav state without custom JS.)
- Only **GET** navigation is boosted. Every **POST** form carries `hx-boost="false"` so mutations do a normal full-page submit — this preserves visible error pages (htmx does not swap non-2xx responses by default) with no downside, since mutations are infrequent.
- `svgchart.HBars` renders semantic **HTML** (not SVG): horizontal bars carry long labels (domain names, full SMTP error strings) that need CSS `text-overflow: ellipsis`. `StackedBars` (the headline volume chart) is SVG as promised. Both are pure server-rendered Go functions returning `template.HTML`.

---

### Task 1: htmx no-flash navigation

**Files:**
- Create: `internal/admin/static/htmx.min.js`
- Modify: `internal/admin/templates/layout.html`
- Modify: `internal/admin/admin.go` (`render`, `renderStatus`, `renderKeys`, `auth`, all render call sites)
- Modify: `internal/admin/templates/login.html`, `email.html`, `domains.html`, `domain.html`, `keys.html` (add `hx-boost="false"` to POST forms)
- Test: `internal/admin/admin_test.go`

**Interfaces:**
- Produces: `render(w http.ResponseWriter, r *http.Request, page string, data any)`, `renderStatus(w, r, status int, page string, data any)`, `renderKeys(w, r, newToken string)`. Fragment rendering keys off request header `HX-Request: true` → executes template `"shell"`; otherwise `"layout"`. `auth` returns header `HX-Redirect: /admin/login` (HTTP 200) for unauthenticated htmx requests.

- [ ] **Step 1: Vendor htmx**

```bash
curl -fsSL https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js -o internal/admin/static/htmx.min.js
wc -c internal/admin/static/htmx.min.js   # expect ~48000 bytes
head -c 60 internal/admin/static/htmx.min.js   # expect a minified JS banner mentioning htmx
```
Expected: file exists, > 40000 bytes. (If the network is unavailable, fetch htmx.org 2.0.4 `dist/htmx.min.js` by any means and place it at that exact path — it must be the real minified library, not a stub.)

- [ ] **Step 2: Write the failing tests**

Add to `internal/admin/admin_test.go` (imports `io`, `net/http`, `strings` are already present):

```go
func TestServesHtmx(t *testing.T) {
	_, srv, c := adminFixture(t)
	resp, err := c.Get(srv.URL + "/admin/static/htmx.min.js")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) < 1000 {
		t.Errorf("htmx.min.js too small: %d bytes", len(body))
	}
}

func TestHXRequestReturnsFragment(t *testing.T) {
	_, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	req, _ := http.NewRequest("GET", srv.URL+"/admin/emails", nil)
	req.Header.Set("HX-Request", "true")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := string(mustRead(t, resp))
	if strings.Contains(body, "<!doctype html>") || strings.Contains(body, "<html") {
		t.Error("HX fragment must not contain the full document")
	}
	if !strings.Contains(body, `id="shell"`) {
		t.Error("fragment must contain the shell element")
	}
}

func TestFullPageWithoutHXRequest(t *testing.T) {
	_, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	resp, err := c.Get(srv.URL + "/admin/emails")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !strings.Contains(string(mustRead(t, resp)), "<!doctype html>") {
		t.Error("normal request must return the full document")
	}
}

func TestExpiredSessionHXRedirect(t *testing.T) {
	_, srv, c := adminFixture(t) // never logs in → unauthenticated
	req, _ := http.NewRequest("GET", srv.URL+"/admin/emails", nil)
	req.Header.Set("HX-Request", "true")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("HX-Redirect"); got != "/admin/login" {
		t.Errorf("HX-Redirect = %q, want /admin/login", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func mustRead(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `go test ./internal/admin/ -run 'TestServesHtmx|TestHXRequestReturnsFragment|TestFullPageWithoutHXRequest|TestExpiredSessionHXRedirect' -v`
Expected: `TestServesHtmx` passes (file is embedded), the fragment test FAILs (no `id="shell"` yet / full doc returned), and `TestExpiredSessionHXRedirect` FAILs (no HX-Redirect header yet).

- [ ] **Step 4: Rewrite `layout.html` into `layout` + `shell`**

Replace the entire contents of `internal/admin/templates/layout.html` with:

```html
{{define "layout"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>doevoe admin</title>
<link rel="icon" href="/admin/static/favicon.svg" type="image/svg+xml">
<link rel="apple-touch-icon" href="/admin/static/apple-touch-icon.png">
<link rel="manifest" href="/admin/static/manifest.webmanifest">
<meta name="theme-color" content="#f5f4ef" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#0f141d" media="(prefers-color-scheme: dark)">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="doevoe">
<link rel="stylesheet" href="/admin/static/doevoe.css">
</head>
<body hx-boost="true" hx-target="#shell" hx-swap="outerHTML">
{{template "shell" .}}
<script src="/admin/static/htmx.min.js"></script>
</body>
</html>{{end}}

{{define "shell"}}<div id="shell">
<header class="topbar">
  <div class="topbar-inner">
    <a class="wordmark" href="/admin/emails">doevoe</a>
    <nav>
      <a href="/admin/emails"{{if eq .Nav "emails"}} class="active" aria-current="page"{{end}}>Emails</a>
      <a href="/admin/domains"{{if eq .Nav "domains"}} class="active" aria-current="page"{{end}}>Domains</a>
      <a href="/admin/keys"{{if eq .Nav "keys"}} class="active" aria-current="page"{{end}}>API keys</a>
    </nav>
    <form method="post" action="/admin/logout" hx-boost="false"><button class="link">Log out</button></form>
  </div>
</header>
<main class="container">
{{template "content" .Data}}
</main>
</div>{{end}}
```

(The `Overview` nav item and the `/admin/` wordmark are added in Task 4, once the dashboard handler exists.)

- [ ] **Step 5: Add `hx-boost="false"` to every POST form**

- `login.html` line 5: `<form method="post" action="/admin/login" class="card login-card">` → add ` hx-boost="false"`.
- `email.html` line 23: `<form method="post" action="/admin/emails/{{.Email.ID}}/retry" class="card">` → add ` hx-boost="false"`.
- `domains.html` line 4: `<form method="post" action="/admin/domains" class="card">` → add ` hx-boost="false"`.
- `domain.html` line 25: `<form method="post" action="/admin/domains/{{.Domain.ID}}/verify" class="actions">` → add ` hx-boost="false"`.
- `keys.html` line 11: `<form method="post" action="/admin/keys" class="card">` → add ` hx-boost="false"`.
- `keys.html` line 34: `<form method="post" action="/admin/keys/{{.ID}}/revoke" class="actions">` → add ` hx-boost="false"`.

- [ ] **Step 6: Update `render`/`renderStatus`/`renderKeys` and `auth` in `admin.go`**

Replace the existing `renderStatus` and `render` (lines ~130-149) with:

```go
func (a *Admin) renderStatus(w http.ResponseWriter, r *http.Request, status int, page string, data any) {
	tpl, err := template.ParseFS(assets, "templates/layout.html", "templates/"+page+".html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	view := struct {
		Nav  string
		Data any
	}{Nav: navSection[page], Data: data}
	// htmx boosted navigation only needs the shell (topbar + main); the
	// full document (head, scripts) is sent for a normal load.
	name := "layout"
	if r.Header.Get("HX-Request") == "true" {
		name = "shell"
	}
	if err := tpl.ExecuteTemplate(w, name, view); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (a *Admin) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	a.renderStatus(w, r, http.StatusOK, page, data)
}
```

Replace `auth` (lines ~111-119) with:

```go
func (a *Admin) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.authed(r) {
			// A 303 body would be swapped into the page shell by htmx; use
			// HX-Redirect so a boosted request expiring mid-session does a
			// full navigation to the login page instead.
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Redirect", "/admin/login")
				w.WriteHeader(http.StatusOK)
				return
			}
			http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
			return
		}
		h(w, r)
	})
}
```

Update every call site to pass `r`:
- Route closure `GET /admin/login`: `a.render(w, r, "login", map[string]any{})`
- `login`: `a.renderStatus(w, r, http.StatusUnauthorized, "login", map[string]any{"Error": "Wrong password"})`
- `listEmails`: `a.render(w, r, "emails", map[string]any{ ... })`
- `showEmail`: `a.render(w, r, "email", ...)`
- `listDomains`: `a.render(w, r, "domains", ...)`
- `showDomain`: `a.render(w, r, "domain", ...)`
- `renderKeys`: change signature to `func (a *Admin) renderKeys(w http.ResponseWriter, r *http.Request, newToken string)` and its final line to `a.render(w, r, "keys", ...)`.
- `listKeys`: `a.renderKeys(w, r, "")`
- `createKey`: `a.renderKeys(w, r, token)`

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/admin/ -v`
Expected: all tests PASS (including the four new ones and the existing suite).

- [ ] **Step 8: Vet + full build**

Run: `go vet ./... && go build ./...`
Expected: no output, exit 0.

- [ ] **Step 9: Commit**

```bash
git add internal/admin/static/htmx.min.js internal/admin/templates internal/admin/admin.go internal/admin/admin_test.go
git commit -m "feat(admin): htmx-boosted navigation without full-page reloads"
```

---

### Task 2: Range-based stats queries

**Files:**
- Create: `internal/store/stats.go`
- Modify: `internal/store/notify.go` (`MonthlyStats`, `TopFailureReasons` → wrappers)
- Test: `internal/store/stats_test.go`

**Interfaces:**
- Produces:
  - `type DayCount struct { Date string; Sent, Failed int }`
  - `type Summary struct { Sent, Failed, Queued, Total int; SuccessRate float64 }`
  - `func (s *Store) DailyVolume(from, to string) ([]DayCount, error)`
  - `func (s *Store) SummaryStats(from, to string) (Summary, error)`
  - `func (s *Store) DomainVolume(from, to string) ([]DomainStats, error)` (reuses existing `DomainStats`)
  - `func (s *Store) FailureReasons(from, to string, limit int) ([]ReasonCount, error)` (reuses existing `ReasonCount`)
- `from`/`to` are RFC3339 UTC strings; the range is half-open `[from, to)`. Buckets key on `created_at`.

- [ ] **Step 1: Write the failing tests**

Create `internal/store/stats_test.go`:

```go
package store

import "testing"

func insertEmail(t *testing.T, s *Store, domainID int64, status, createdAt, lastErr string) {
	t.Helper()
	_, err := s.db.Exec(`INSERT INTO emails
		(domain_id, from_addr, to_addr, subject, status, next_attempt_at, last_error, created_at)
		VALUES (?, 'from@x.test', 'to@y.test', 'subj', ?, ?, ?, ?)`,
		domainID, status, createdAt, lastErr, createdAt)
	if err != nil {
		t.Fatal(err)
	}
}

func TestDailyVolumeBuckets(t *testing.T) {
	s := testStore(t)
	d, err := s.CreateDomain("a.test", "mail1", "pk")
	if err != nil {
		t.Fatal(err)
	}
	insertEmail(t, s, d.ID, "sent", "2026-07-01T10:00:00Z", "")
	insertEmail(t, s, d.ID, "sent", "2026-07-01T11:00:00Z", "")
	insertEmail(t, s, d.ID, "failed", "2026-07-02T09:00:00Z", "boom")
	got, err := s.DailyVolume("2026-07-01T00:00:00Z", "2026-07-03T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 days, got %d (%+v)", len(got), got)
	}
	if got[0].Date != "2026-07-01" || got[0].Sent != 2 || got[0].Failed != 0 {
		t.Errorf("day0 = %+v", got[0])
	}
	if got[1].Date != "2026-07-02" || got[1].Failed != 1 {
		t.Errorf("day1 = %+v", got[1])
	}
}

func TestSummaryStats(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("a.test", "mail1", "pk")
	insertEmail(t, s, d.ID, "sent", "2026-07-01T10:00:00Z", "")
	insertEmail(t, s, d.ID, "failed", "2026-07-01T10:00:00Z", "boom")
	insertEmail(t, s, d.ID, "queued", "2026-07-01T10:00:00Z", "")
	sm, err := s.SummaryStats("2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if sm.Sent != 1 || sm.Failed != 1 || sm.Queued != 1 || sm.Total != 3 {
		t.Errorf("summary = %+v", sm)
	}
	if sm.SuccessRate < 33.3 || sm.SuccessRate > 33.4 {
		t.Errorf("success rate = %v, want ~33.33", sm.SuccessRate)
	}
}

func TestSummaryStatsEmptyNoDivideByZero(t *testing.T) {
	s := testStore(t)
	sm, err := s.SummaryStats("2026-07-01T00:00:00Z", "2026-08-01T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if sm.Total != 0 || sm.SuccessRate != 0 {
		t.Errorf("empty summary = %+v", sm)
	}
}

func TestDomainVolume(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("a.test", "mail1", "pk")
	insertEmail(t, s, d.ID, "sent", "2026-07-01T10:00:00Z", "")
	insertEmail(t, s, d.ID, "failed", "2026-07-01T10:00:00Z", "x")
	got, err := s.DomainVolume("2026-07-01T00:00:00Z", "2026-07-02T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].DomainName != "a.test" || got[0].Sent != 1 || got[0].Failed != 1 {
		t.Errorf("domain volume = %+v", got)
	}
}

func TestFailureReasons(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("a.test", "mail1", "pk")
	insertEmail(t, s, d.ID, "failed", "2026-07-01T10:00:00Z", "550 mailbox full")
	insertEmail(t, s, d.ID, "failed", "2026-07-01T11:00:00Z", "550 mailbox full")
	insertEmail(t, s, d.ID, "failed", "2026-07-01T12:00:00Z", "timeout")
	got, err := s.FailureReasons("2026-07-01T00:00:00Z", "2026-07-02T00:00:00Z", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Reason != "550 mailbox full" || got[0].Count != 2 {
		t.Errorf("reasons = %+v", got)
	}
}

func TestMonthlyStatsWrapperEquivalent(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("a.test", "mail1", "pk")
	insertEmail(t, s, d.ID, "sent", "2026-06-15T10:00:00Z", "")
	insertEmail(t, s, d.ID, "failed", "2026-06-16T10:00:00Z", "x")
	insertEmail(t, s, d.ID, "sent", "2026-07-01T10:00:00Z", "") // next month, excluded
	stats, err := s.MonthlyStats("2026-06")
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 1 || stats[0].Sent != 1 || stats[0].Failed != 1 {
		t.Errorf("monthly stats = %+v", stats)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/store/ -run 'TestDailyVolumeBuckets|TestSummaryStats|TestDomainVolume|TestFailureReasons' -v`
Expected: FAIL — `s.DailyVolume` / `s.SummaryStats` / `s.DomainVolume` / `s.FailureReasons` undefined.

- [ ] **Step 3: Create `internal/store/stats.go`**

```go
package store

import "time"

type DayCount struct {
	Date         string // YYYY-MM-DD (UTC)
	Sent, Failed int
}

type Summary struct {
	Sent, Failed, Queued, Total int
	SuccessRate                 float64 // 0..100; 0 when Total == 0
}

// DailyVolume returns per-day sent/failed counts for emails created in the
// half-open range [from, to). Days with no emails are omitted (the caller
// fills gaps for a continuous axis).
func (s *Store) DailyVolume(from, to string) ([]DayCount, error) {
	rows, err := s.db.Query(`SELECT substr(created_at,1,10) AS day,
		SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END),
		SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END)
		FROM emails
		WHERE created_at >= ? AND created_at < ?
		GROUP BY day ORDER BY day`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DayCount
	for rows.Next() {
		var d DayCount
		if err := rows.Scan(&d.Date, &d.Sent, &d.Failed); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// SummaryStats returns headline totals for emails created in [from, to).
func (s *Store) SummaryStats(from, to string) (Summary, error) {
	var sm Summary
	// COALESCE guards the all-NULL row SQLite returns when nothing matches.
	err := s.db.QueryRow(`SELECT
		COALESCE(SUM(CASE WHEN status='sent' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END), 0),
		COALESCE(SUM(CASE WHEN status IN ('queued','sending') THEN 1 ELSE 0 END), 0),
		COUNT(*)
		FROM emails WHERE created_at >= ? AND created_at < ?`, from, to).
		Scan(&sm.Sent, &sm.Failed, &sm.Queued, &sm.Total)
	if err != nil {
		return Summary{}, err
	}
	if sm.Total > 0 {
		sm.SuccessRate = float64(sm.Sent) / float64(sm.Total) * 100
	}
	return sm, nil
}

// DomainVolume returns per-domain sent/failed counts for [from, to).
func (s *Store) DomainVolume(from, to string) ([]DomainStats, error) {
	rows, err := s.db.Query(`SELECT d.name,
		SUM(CASE WHEN e.status='sent' THEN 1 ELSE 0 END),
		SUM(CASE WHEN e.status='failed' THEN 1 ELSE 0 END)
		FROM emails e JOIN domains d ON d.id=e.domain_id
		WHERE e.created_at >= ? AND e.created_at < ?
		GROUP BY d.name ORDER BY d.name`, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainStats
	for rows.Next() {
		var st DomainStats
		if err := rows.Scan(&st.DomainName, &st.Sent, &st.Failed); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// FailureReasons returns the most common last_error values among failed
// emails created in [from, to), most frequent first.
func (s *Store) FailureReasons(from, to string, limit int) ([]ReasonCount, error) {
	rows, err := s.db.Query(`SELECT last_error, COUNT(*) FROM emails
		WHERE status='failed' AND created_at >= ? AND created_at < ? AND last_error != ''
		GROUP BY last_error ORDER BY COUNT(*) DESC LIMIT ?`, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReasonCount
	for rows.Next() {
		var rc ReasonCount
		if err := rows.Scan(&rc.Reason, &rc.Count); err != nil {
			return nil, err
		}
		out = append(out, rc)
	}
	return out, rows.Err()
}

// monthRange converts a "2006-01" month prefix to the half-open UTC range
// [firstOfMonth, firstOfNextMonth). Because store timestamps are fixed-width
// RFC3339 UTC strings, this range is lexicographically equivalent to the old
// `created_at LIKE 'YYYY-MM%'` filter.
func monthRange(monthPrefix string) (from, to string) {
	t, err := time.Parse("2006-01", monthPrefix)
	if err != nil {
		// Defensive: a malformed prefix scopes to its literal string range.
		return monthPrefix, monthPrefix + "￿"
	}
	return FmtTime(t), FmtTime(t.AddDate(0, 1, 0))
}
```

- [ ] **Step 4: Refactor `notify.go` wrappers**

In `internal/store/notify.go`, replace the bodies of `MonthlyStats` and `TopFailureReasons` (lines ~61-81 and ~92-107) with:

```go
func (s *Store) MonthlyStats(monthPrefix string) ([]DomainStats, error) {
	from, to := monthRange(monthPrefix)
	return s.DomainVolume(from, to)
}
```

```go
func (s *Store) TopFailureReasons(monthPrefix string, limit int) ([]ReasonCount, error) {
	from, to := monthRange(monthPrefix)
	return s.FailureReasons(from, to, limit)
}
```

Leave `DomainStats`, `ReasonCount`, and `FailureRate` untouched.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `go test ./internal/store/ ./internal/notify/ -v`
Expected: PASS — the new stats tests, the existing store `TestMonthlyStats`, and all notifier tests (which call the now-wrapped `MonthlyStats`/`TopFailureReasons`).

- [ ] **Step 6: Commit**

```bash
git add internal/store/stats.go internal/store/stats_test.go internal/store/notify.go
git commit -m "feat(store): range-based volume/summary/failure stats queries"
```

---

### Task 3: svgchart package

**Files:**
- Create: `internal/svgchart/svgchart.go`
- Test: `internal/svgchart/svgchart_test.go`

**Interfaces:**
- Produces:
  - `type DayBar struct { Label string; Sent, Failed int }`
  - `type HBar struct { Label string; Value int }`
  - `func StackedBars(days []DayBar) template.HTML` — SVG, sent (green) stacked under failed (red).
  - `func HBars(bars []HBar) template.HTML` — HTML rows (`.hbars > .hbar > .hbar-label/.hbar-track > .hbar-fill/.hbar-value`), max value scaled to full width.
  - Both render `<p class="empty">No data for this range.</p>` for empty/all-zero input and never divide by zero.

- [ ] **Step 1: Write the failing tests**

Create `internal/svgchart/svgchart_test.go`:

```go
package svgchart

import (
	"strings"
	"testing"
)

func TestStackedBarsRendersColoredRects(t *testing.T) {
	out := string(StackedBars([]DayBar{
		{Label: "07-01", Sent: 2, Failed: 1},
		{Label: "07-02", Sent: 3, Failed: 0},
	}))
	if !strings.Contains(out, "<svg") {
		t.Error("expected an <svg> element")
	}
	if !strings.Contains(out, "var(--green)") {
		t.Error("expected green (sent) bars")
	}
	if !strings.Contains(out, "var(--red)") {
		t.Error("expected red (failed) bars")
	}
	if !strings.Contains(out, `role="img"`) {
		t.Error("expected role=img for accessibility")
	}
}

func TestStackedBarsEmptyIsPlaceholder(t *testing.T) {
	if !strings.Contains(string(StackedBars(nil)), "No data") {
		t.Error("empty input should render the placeholder")
	}
}

func TestStackedBarsAllZeroIsPlaceholder(t *testing.T) {
	out := string(StackedBars([]DayBar{{Label: "07-01"}, {Label: "07-02"}}))
	if !strings.Contains(out, "No data") {
		t.Errorf("all-zero input should render placeholder, got %q", out)
	}
}

func TestHBarsScalesAndEscapes(t *testing.T) {
	out := string(HBars([]HBar{
		{Label: "<script>", Value: 10},
		{Label: "b.test", Value: 5},
	}))
	if strings.Contains(out, "<script>") {
		t.Error("label must be HTML-escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected escaped label")
	}
	if !strings.Contains(out, "width:100.0%") {
		t.Error("largest bar should be full width")
	}
	if !strings.Contains(out, "width:50.0%") {
		t.Error("half-value bar should be 50%")
	}
}

func TestHBarsEmptyIsPlaceholder(t *testing.T) {
	if !strings.Contains(string(HBars(nil)), "No data") {
		t.Error("empty input should render the placeholder")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/svgchart/ -v`
Expected: FAIL — package/functions undefined.

- [ ] **Step 3: Create `internal/svgchart/svgchart.go`**

```go
// Package svgchart renders small, dependency-free charts as HTML/SVG strings
// for the admin dashboard. Colors reference the CSS custom properties defined
// in the admin stylesheet, so charts follow the light/dark theme automatically.
package svgchart

import (
	"fmt"
	"html/template"
	"strings"
)

// DayBar is one day's column in a StackedBars chart.
type DayBar struct {
	Label        string
	Sent, Failed int
}

// HBar is one row in an HBars chart.
type HBar struct {
	Label string
	Value int
}

func placeholder() template.HTML {
	return template.HTML(`<p class="empty">No data for this range.</p>`)
}

// StackedBars renders daily volume as stacked columns: sent (green) at the
// bottom, failed (red) above it. Returns a placeholder when there is nothing
// to plot.
func StackedBars(days []DayBar) template.HTML {
	max := 0
	for _, d := range days {
		if t := d.Sent + d.Failed; t > max {
			max = t
		}
	}
	if max == 0 {
		return placeholder()
	}
	const (
		plotH = 120.0 // plot area height in viewBox units
		step  = 20.0  // column pitch
		gap   = 3.0   // gap each side of a bar
	)
	w := float64(len(days)) * step
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" class="chart" role="img" aria-label="Daily email volume: sent and failed" preserveAspectRatio="none" style="width:100%%;height:auto">`, w, plotH)
	b.WriteString(`<title>Daily email volume</title>`)
	for i, d := range days {
		x := float64(i)*step + gap
		bw := step - gap*2
		sentH := float64(d.Sent) / float64(max) * plotH
		failH := float64(d.Failed) / float64(max) * plotH
		if sentH > 0 {
			fmt.Fprintf(&b, `<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="var(--green)"/>`,
				x, plotH-sentH, bw, sentH)
		}
		if failH > 0 {
			fmt.Fprintf(&b, `<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="var(--red)"/>`,
				x, plotH-sentH-failH, bw, failH)
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// HBars renders horizontal bars as semantic HTML (so long labels ellipsize),
// with the largest value scaled to full track width. Returns a placeholder
// when there is nothing to plot.
func HBars(bars []HBar) template.HTML {
	max := 0
	for _, x := range bars {
		if x.Value > max {
			max = x.Value
		}
	}
	if max == 0 {
		return placeholder()
	}
	var b strings.Builder
	b.WriteString(`<div class="hbars">`)
	for _, x := range bars {
		pct := float64(x.Value) / float64(max) * 100
		label := template.HTMLEscapeString(x.Label)
		fmt.Fprintf(&b, `<div class="hbar"><span class="hbar-label" title="%s">%s</span><span class="hbar-track"><span class="hbar-fill" style="width:%.1f%%"></span></span><span class="hbar-value">%d</span></div>`,
			label, label, pct, x.Value)
	}
	b.WriteString(`</div>`)
	return template.HTML(b.String())
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/svgchart/ -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/svgchart/
git commit -m "feat(svgchart): dependency-free stacked-bar and horizontal-bar charts"
```

---

### Task 4: Overview dashboard page

**Files:**
- Modify: `internal/admin/admin.go` (add `dashboard` handler, route, `navSection`, imports; add `Overview` nav + `/admin/` wordmark to `shell`)
- Modify: `internal/admin/templates/layout.html` (`shell`: add Overview nav item, wordmark → `/admin/`)
- Create: `internal/admin/templates/dashboard.html`
- Modify: `internal/admin/static/doevoe.css` (append dashboard styles)
- Test: `internal/admin/admin_test.go`

**Interfaces:**
- Consumes: `store.SummaryStats`, `store.DailyVolume`, `store.DomainVolume`, `store.FailureReasons` (Task 2); `svgchart.DayBar/HBar/StackedBars/HBars` (Task 3); `render(w, r, "dashboard", data)` (Task 1).
- Produces: `GET /admin/{$}` renders the Overview dashboard; `?range=` accepts `7|30|90` (default 30).

- [ ] **Step 1: Write the failing tests**

Add to `internal/admin/admin_test.go`:

```go
func TestDashboardShowsKPIs(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, err := s.CreateDomain("a.test", "mail1", "pk")
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@a.test", To: "b@b.test", Subject: "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.MarkSent(id, store.Now()); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(srv.URL + "/admin/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	body := string(mustRead(t, resp))
	if !strings.Contains(body, "Success rate") {
		t.Error("dashboard should show the success-rate KPI")
	}
	if !strings.Contains(body, "Overview") {
		t.Error("dashboard should show the Overview heading/nav")
	}
}

func TestDashboardRangeToggle(t *testing.T) {
	_, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	resp, err := c.Get(srv.URL + "/admin/?range=7")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	// The 7d control should be marked active.
	if !strings.Contains(string(mustRead(t, resp)), `href="/admin/?range=7" class="active"`) {
		t.Error("range=7 should mark the 7d toggle active")
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/admin/ -run 'TestDashboardShowsKPIs|TestDashboardRangeToggle' -v`
Expected: FAIL — `/admin/` still redirects to `/admin/emails` (303/no KPIs).

- [ ] **Step 3: Add imports, route, `navSection`, and handler in `admin.go`**

Add to the import block: `"sort"` and `"doevoe/internal/svgchart"`.

In `Routes`, replace the `GET /admin/{$}` redirect handler with:

```go
	mux.Handle("GET /admin/{$}", a.auth(a.dashboard))
```

In `navSection`, add the dashboard entry:

```go
var navSection = map[string]string{
	"dashboard": "dashboard",
	"emails":    "emails", "email": "emails",
	"domains": "domains", "domain": "domains",
	"keys": "keys",
}
```

Add the handler (near the other handlers):

```go
func (a *Admin) dashboard(w http.ResponseWriter, r *http.Request) {
	days := 30
	switch r.URL.Query().Get("range") {
	case "7":
		days = 7
	case "90":
		days = 90
	}
	// Half-open window covering the last `days` full UTC calendar days.
	now := time.Now().UTC()
	startDay := now.Truncate(24 * time.Hour).AddDate(0, 0, -(days - 1))
	from := store.FmtTime(startDay)
	to := store.FmtTime(startDay.AddDate(0, 0, days))

	summary, err := a.Store.SummaryStats(from, to)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	daily, _ := a.Store.DailyVolume(from, to)
	domainStats, _ := a.Store.DomainVolume(from, to)
	reasons, _ := a.Store.FailureReasons(from, to, 8)

	// Fill gaps so the time axis is continuous across the whole range.
	byDay := map[string]store.DayCount{}
	for _, d := range daily {
		byDay[d.Date] = d
	}
	bars := make([]svgchart.DayBar, 0, days)
	for i := 0; i < days; i++ {
		day := startDay.AddDate(0, 0, i)
		dc := byDay[day.Format("2006-01-02")]
		bars = append(bars, svgchart.DayBar{Label: day.Format("01-02"), Sent: dc.Sent, Failed: dc.Failed})
	}

	domainBars := make([]svgchart.HBar, 0, len(domainStats))
	for _, d := range domainStats {
		domainBars = append(domainBars, svgchart.HBar{Label: d.DomainName, Value: d.Sent + d.Failed})
	}
	sort.Slice(domainBars, func(i, j int) bool { return domainBars[i].Value > domainBars[j].Value })

	reasonBars := make([]svgchart.HBar, 0, len(reasons))
	for _, rc := range reasons {
		reasonBars = append(reasonBars, svgchart.HBar{Label: rc.Reason, Value: rc.Count})
	}

	a.render(w, r, "dashboard", map[string]any{
		"Days":        days,
		"Summary":     summary,
		"VolumeChart": svgchart.StackedBars(bars),
		"DomainChart": svgchart.HBars(domainBars),
		"ReasonChart": svgchart.HBars(reasonBars),
	})
}
```

- [ ] **Step 4: Add the Overview nav item and update the wordmark in `shell`**

In `internal/admin/templates/layout.html`, inside `{{define "shell"}}`:
- Change the wordmark to `<a class="wordmark" href="/admin/">doevoe</a>`.
- Add as the first nav link: `<a href="/admin/"{{if eq .Nav "dashboard"}} class="active" aria-current="page"{{end}}>Overview</a>`

- [ ] **Step 5: Create `internal/admin/templates/dashboard.html`**

```html
{{define "content"}}
<div class="page-head">
  <h1>Overview</h1>
  <div class="range-toggle">
    <a href="/admin/?range=7"{{if eq .Days 7}} class="active"{{end}}>7d</a>
    <a href="/admin/?range=30"{{if eq .Days 30}} class="active"{{end}}>30d</a>
    <a href="/admin/?range=90"{{if eq .Days 90}} class="active"{{end}}>90d</a>
  </div>
</div>

<div class="kpis">
  <div class="kpi"><span class="kpi-num">{{.Summary.Sent}}</span><span class="kpi-label">Sent</span></div>
  <div class="kpi"><span class="kpi-num">{{printf "%.1f%%" .Summary.SuccessRate}}</span><span class="kpi-label">Success rate</span></div>
  <div class="kpi"><span class="kpi-num">{{.Summary.Failed}}</span><span class="kpi-label">Failed</span></div>
  <div class="kpi"><span class="kpi-num">{{.Summary.Queued}}</span><span class="kpi-label">In flight</span></div>
</div>

<h2 class="section-title">Volume over time</h2>
<div class="card chart-card">
  {{.VolumeChart}}
  <div class="chart-legend"><span class="lg lg-sent">Sent</span><span class="lg lg-failed">Failed</span></div>
</div>

<h2 class="section-title">Volume by domain</h2>
<div class="card">{{.DomainChart}}</div>

<h2 class="section-title">Top failure reasons</h2>
<div class="card">{{.ReasonChart}}</div>
{{end}}
```

- [ ] **Step 6: Append dashboard styles to `doevoe.css`**

Append to `internal/admin/static/doevoe.css`:

```css
/* ---- dashboard ---------------------------------------------------------- */
.range-toggle { display: inline-flex; gap: .25rem; margin-left: auto; margin-bottom: .35rem; }
.range-toggle a {
  text-decoration: none; font-size: .78rem; font-weight: 600;
  padding: .35rem .6rem; border: 1px solid var(--line); border-radius: .5rem;
  color: var(--muted); background: var(--card);
}
.range-toggle a.active { color: var(--ink); border-color: var(--ink); }
.kpis {
  display: grid; grid-template-columns: repeat(2, 1fr); gap: .7rem; margin-bottom: .4rem;
}
.kpi {
  background: var(--card); border: 1px solid var(--line);
  border-radius: .65rem; padding: .9rem 1rem;
  display: flex; flex-direction: column; gap: .2rem;
}
.kpi-num { font-size: 1.5rem; font-weight: 750; letter-spacing: -.03em; }
.kpi-label {
  font-size: .7rem; font-weight: 600; letter-spacing: .07em;
  text-transform: uppercase; color: var(--muted);
}
.chart-card .chart { display: block; }
.chart-legend { display: flex; gap: 1rem; margin-top: .6rem; font-size: .72rem; color: var(--muted); }
.chart-legend .lg::before {
  content: ""; display: inline-block; width: .6em; height: .6em;
  border-radius: 2px; margin-right: .35em;
}
.chart-legend .lg-sent::before { background: var(--green); }
.chart-legend .lg-failed::before { background: var(--red); }
.hbars { display: grid; gap: .5rem; }
.hbar { display: grid; grid-template-columns: 8rem 1fr 2.5rem; align-items: center; gap: .6rem; font-size: .78rem; }
.hbar-label { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--ink); }
.hbar-track { background: var(--inset); border-radius: 3px; height: 1rem; overflow: hidden; }
.hbar-fill { display: block; height: 100%; background: var(--blue); }
.hbar-value { text-align: right; color: var(--muted); font-family: var(--font-mono); }
@media (min-width: 48rem) {
  .kpis { grid-template-columns: repeat(4, 1fr); }
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `go test ./internal/admin/ -v`
Expected: all PASS (dashboard + existing suite).

- [ ] **Step 8: Full vet, build, and test**

Run: `go vet ./... && go build ./... && go test ./...`
Expected: no output from vet/build; all packages PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/admin/admin.go internal/admin/templates/layout.html internal/admin/templates/dashboard.html internal/admin/static/doevoe.css internal/admin/admin_test.go
git commit -m "feat(admin): Overview dashboard with volume, success, domain and failure charts"
```

---

## Self-Review

**Spec coverage:**
- No screen-flashes → Task 1 (htmx boost, shell swap, progressive enhancement, HX-Redirect on auth expiry). ✓
- Single-binary / no build step → htmx vendored + embedded; CI unchanged (Global Constraints). ✓
- Server-rendered SVG charts → Task 3 (`StackedBars` SVG; `HBars` HTML for long labels — documented deviation). ✓
- Volume over time / success KPIs / volume by domain / top failure reasons → Task 4 template + handler. ✓
- Range queries + monthly-wrapper refactor preserving notifier behavior → Task 2 (+ `TestMonthlyStatsWrapperEquivalent`, existing notifier tests). ✓
- 7/30/90 range toggle, default 30, invalid → 30 → Task 4 handler `switch`. ✓
- Overview as landing page → Task 4 (`GET /admin/{$}` → dashboard, wordmark/nav). ✓
- Empty-data placeholders + divide-by-zero guards → Task 2 (`SuccessRate` guard) + Task 3 (`placeholder()`), with tests. ✓
- UTC bucketing → Task 2 SQL + Task 4 window math. ✓

**Placeholder scan:** No TBD/TODO; every code/test step contains complete code and exact run commands with expected output.

**Type consistency:** `render(w, r, page, data)`, `renderStatus(w, r, status, page, data)`, `renderKeys(w, r, newToken)` used consistently across Tasks 1 and 4. `DayCount`/`Summary`/`DayBar`/`HBar` field names match between store (Task 2), svgchart (Task 3), and the handler (Task 4). Handler map keys (`Days`, `Summary`, `VolumeChart`, `DomainChart`, `ReasonChart`) match `dashboard.html`. CSS class names (`hbars`/`hbar`/`hbar-label`/`hbar-track`/`hbar-fill`/`hbar-value`, `chart`, `kpis`/`kpi`, `range-toggle`) match `HBars` output, `StackedBars` output, and the template.
