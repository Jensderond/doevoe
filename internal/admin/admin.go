package admin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"doevoe/internal/delivery"
	"doevoe/internal/dkimkeys"
	"doevoe/internal/dnscheck"
	"doevoe/internal/domains"
	"doevoe/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Admin struct {
	Store                                    *store.Store
	Password, EgressIP, AdminEmail, Hostname string
	// DMARCRua is the mailbox that DMARC aggregate reports get sent to
	// (the built-in receiver's report address, e.g. "dmarc@<SystemDomain>"),
	// used as the rua= value in a sending domain's DMARC record.
	DMARCRua string
	// SystemDomain is the domain doevoe's built-in DMARC report receiver
	// lives under; when a domain's page matches it, showDomain also
	// renders SystemRecords (the one-time MX/TXT setup for the receiver).
	SystemDomain               string
	OnKeyCreated, OnKeyRevoked func(name, domainName string)
	CheckDomain                func(ctx context.Context, d *store.Domain) dnscheck.Result

	// loginFailDelay is slept before responding to a failed login attempt,
	// to throttle password-guessing. Defaults to 1s (see New); tests set it
	// to 0 so the bad-password test cases stay fast.
	loginFailDelay time.Duration

	mu       sync.Mutex
	sessions map[string]time.Time
}

func New(s *store.Store, password, egressIP, adminEmail, hostname string) *Admin {
	return &Admin{Store: s, Password: password, EgressIP: egressIP,
		AdminEmail: adminEmail, Hostname: hostname, sessions: map[string]time.Time{},
		loginFailDelay: 1 * time.Second}
}

func (a *Admin) Routes(mux *http.ServeMux) {
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /admin/static/", http.StripPrefix("/admin/static/", http.FileServer(http.FS(static))))
	mux.HandleFunc("GET /admin/login", func(w http.ResponseWriter, r *http.Request) {
		a.render(w, r, "login", map[string]any{})
	})
	mux.HandleFunc("POST /admin/login", a.login)
	mux.Handle("POST /admin/logout", a.auth(a.logout))
	mux.Handle("GET /admin/{$}", a.auth(a.dashboard))
	mux.Handle("GET /admin/emails", a.auth(a.listEmails))
	mux.Handle("GET /admin/emails/{id}", a.auth(a.showEmail))
	mux.Handle("POST /admin/emails/{id}/retry", a.auth(a.retryEmail))
	mux.Handle("POST /admin/emails/{id}/cancel", a.auth(a.cancelEmail))
	mux.Handle("GET /admin/dmarc", a.auth(a.dmarcPage))
	mux.Handle("GET /admin/domains", a.auth(a.listDomains))
	mux.Handle("POST /admin/domains", a.auth(a.createDomain))
	mux.Handle("GET /admin/domains/{id}", a.auth(a.showDomain))
	mux.Handle("POST /admin/domains/{id}/verify", a.auth(a.verifyDomain))
	mux.Handle("POST /admin/domains/{id}/provider", a.auth(a.setDomainProvider))
	mux.Handle("GET /admin/keys", a.auth(a.listKeys))
	mux.Handle("POST /admin/keys", a.auth(a.createKey))
	mux.Handle("POST /admin/keys/{id}/revoke", a.auth(a.revokeKey))
}

func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(a.Password)) != 1 {
		slog.Warn("admin login failed", "remote", r.RemoteAddr)
		if a.loginFailDelay > 0 {
			time.Sleep(a.loginFailDelay)
		}
		a.renderStatus(w, r, http.StatusUnauthorized, "login", map[string]any{"Error": "Wrong password"})
		return
	}
	a.newSession(w)
	http.Redirect(w, r, "/admin/emails", http.StatusSeeOther)
}

func (a *Admin) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("doevoe_session"); err == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "doevoe_session", Path: "/admin", MaxAge: -1})
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}

func (a *Admin) authed(r *http.Request) bool {
	c, err := r.Cookie("doevoe_session")
	if err != nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	exp, ok := a.sessions[c.Value]
	if !ok || time.Now().After(exp) {
		delete(a.sessions, c.Value)
		return false
	}
	return true
}

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

// navSection maps a rendered page name to the topbar nav item it should
// highlight as active (detail pages like "email"/"domain" highlight their
// parent list page).
var navSection = map[string]string{
	"dashboard": "dashboard",
	"emails":    "emails", "email": "emails",
	"domains": "domains", "domain": "domains",
	"keys":  "keys",
	"dmarc": "dmarc",
}

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
	// htmx boosted navigation only needs the shell (topbar + main); the full
	// document (head, scripts) is sent for a normal load.
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

func (a *Admin) newSession(w http.ResponseWriter) {
	buf := make([]byte, 16)
	rand.Read(buf)
	token := hex.EncodeToString(buf)
	a.mu.Lock()
	a.sessions[token] = time.Now().Add(7 * 24 * time.Hour)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "doevoe_session", Value: token,
		Path: "/admin", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 7 * 24 * 3600})
}

// parseFilterDate parses a YYYY-MM-DD query value into a UTC day start.
// Unparseable values are treated as unset (ok=false), matching the
// forgiving handling of the other filters.
func parseFilterDate(v string) (day time.Time, ok bool) {
	t, err := time.ParseInLocation("2006-01-02", v, time.UTC)
	return t, err == nil
}

// emailRange is one of the period chips on the email list. days is a rolling
// window ending "now"; 0 means unbounded ("All time").
type emailRange struct {
	Key   string // the `range` query value, e.g. "7d"
	Label string // chip text
	Title string // spelled-out window, used for the chip tooltip and page summary
	days  int
}

var emailRanges = []emailRange{
	{Key: "1d", Label: "24h", Title: "Last 24 hours", days: 1},
	{Key: "7d", Label: "7d", Title: "Last 7 days", days: 7},
	{Key: "30d", Label: "30d", Title: "Last 30 days", days: 30},
	{Key: "90d", Label: "90d", Title: "Last 90 days", days: 90},
	{Key: "all", Label: "All", Title: "All time", days: 0},
}

// defaultEmailRange is the window a bare /admin/emails shows. The list is
// bounded by default so the common case (what happened recently) doesn't page
// through months of history; the "All" chip is the way out.
const defaultEmailRange = "7d"

func lookupEmailRange(key string) (emailRange, bool) {
	for _, r := range emailRanges {
		if r.Key == key {
			return r, true
		}
	}
	return emailRange{}, false
}

// emailWindow is the resolved created_at window for one email-list render:
// the store bounds, the form state that produced them, and a label for the
// page. Range is either a preset key or "custom".
type emailWindow struct {
	Range       string
	FromDate    string // YYYY-MM-DD as submitted, echoed back into the date inputs
	ToDate      string
	CreatedFrom string // RFC3339 bounds for store.EmailFilter
	CreatedTo   string
	Label       string
}

// rangeChip is one rendered period chip: the active one is inert, the rest are
// links that keep the status/domain/search filters and drop any custom dates.
type rangeChip struct {
	Key, Label, Title, URL string
	Active                 bool
}

// filterState summarizes the non-period filters for the collapsed filter
// header, so what's still narrowing the list stays visible when the panel is
// shut. Empty when nothing but the period is set.
func filterState(status, search string, domainID int64, domains []*store.Domain) string {
	var parts []string
	if status != "" {
		parts = append(parts, status)
	}
	for _, d := range domains {
		if d.ID == domainID {
			parts = append(parts, d.Name)
		}
	}
	if search != "" {
		parts = append(parts, `"`+search+`"`)
	}
	return strings.Join(parts, " · ")
}

func presetWindow(r emailRange, now time.Time) emailWindow {
	win := emailWindow{Range: r.Key, Label: r.Title}
	if r.days > 0 {
		win.CreatedFrom = store.FmtTime(now.AddDate(0, 0, -r.days))
	}
	return win
}

// customWindow builds the window for two YYYY-MM-DD form values. It reports
// false when neither parses, so the caller can fall back to a preset instead
// of silently listing everything.
func customWindow(fromRaw, toRaw string) (emailWindow, bool) {
	win := emailWindow{Range: "custom"}
	if d, ok := parseFilterDate(fromRaw); ok {
		win.FromDate, win.CreatedFrom = fromRaw, store.FmtTime(d)
	}
	if d, ok := parseFilterDate(toRaw); ok {
		// CreatedTo is exclusive; bump to the next day so the picked
		// "to" date itself is included, as a human would expect.
		win.ToDate, win.CreatedTo = toRaw, store.FmtTime(d.AddDate(0, 0, 1))
	}
	switch {
	case win.FromDate != "" && win.ToDate != "":
		win.Label = win.FromDate + " → " + win.ToDate
	case win.FromDate != "":
		win.Label = "From " + win.FromDate
	case win.ToDate != "":
		win.Label = "Up to " + win.ToDate
	default:
		return emailWindow{}, false
	}
	return win, true
}

// resolveEmailWindow decides which period the email list shows, in order:
//
//  1. a parseable from/to — dates always win, which is what makes filling
//     them in switch the period to a custom range. The period chips are links
//     that carry no dates, so picking one clears them;
//  2. range=<preset> — the rolling window. The filter form posts this back as
//     a hidden field so applying a status or search keeps the current period;
//  3. nothing usable, including range=custom with no parseable date — the
//     default window.
//
// Nothing here can error out: like the other filters, junk degrades to a
// sensible list rather than a 400.
func resolveEmailWindow(q url.Values, now time.Time) emailWindow {
	if win, ok := customWindow(q.Get("from"), q.Get("to")); ok {
		return win
	}
	if r, ok := lookupEmailRange(q.Get("range")); ok {
		return presetWindow(r, now)
	}
	def, _ := lookupEmailRange(defaultEmailRange)
	return presetWindow(def, now)
}

// dashboardData is embedded as JSON in the dashboard page (the
// #dashboard-data script tag) for static/charts.js to render client-side.
type dashboardData struct {
	RangeDays int           `json:"rangeDays"`
	Daily     []chartDay    `json:"daily"`   // gap-filled, oldest→newest
	Domains   []chartDomain `json:"domains"` // sorted by sent+failed desc
	Reasons   []chartReason `json:"reasons"` // most frequent first
}

type chartDay struct {
	Date   string `json:"date"` // YYYY-MM-DD (UTC)
	Sent   int    `json:"sent"`
	Failed int    `json:"failed"`
}

type chartDomain struct {
	Name   string `json:"name"`
	Sent   int    `json:"sent"`
	Failed int    `json:"failed"`
}

type chartReason struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

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
	startDay := now.Truncate(24*time.Hour).AddDate(0, 0, -(days - 1))
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

	// Fill gaps so the time axis is continuous across the whole range.
	byDay := map[string]store.DayCount{}
	for _, d := range daily {
		byDay[d.Date] = d
	}
	data := dashboardData{
		RangeDays: days,
		Daily:     make([]chartDay, 0, days),
		Domains:   make([]chartDomain, 0, len(domainStats)),
		Reasons:   make([]chartReason, 0, len(reasons)),
	}
	for i := 0; i < days; i++ {
		date := startDay.AddDate(0, 0, i).Format("2006-01-02")
		dc := byDay[date]
		data.Daily = append(data.Daily, chartDay{Date: date, Sent: dc.Sent, Failed: dc.Failed})
	}
	for _, d := range domainStats {
		data.Domains = append(data.Domains, chartDomain{Name: d.DomainName, Sent: d.Sent, Failed: d.Failed})
	}
	sort.SliceStable(data.Domains, func(i, j int) bool {
		return data.Domains[i].Sent+data.Domains[i].Failed > data.Domains[j].Sent+data.Domains[j].Failed
	})
	for _, rc := range reasons {
		data.Reasons = append(data.Reasons, chartReason{Reason: rc.Reason, Count: rc.Count})
	}

	// json.Marshal escapes <, > and & by default, so a reason string can never
	// smuggle "</script>" into the page; template.JS then keeps html/template
	// from re-escaping the JSON inside the script tag.
	blob, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	a.render(w, r, "dashboard", map[string]any{
		"Days":               days,
		"Summary":            summary,
		"DataJSON":           template.JS(blob),
		"BlocklistChecked":   len(blStatus) > 0,
		"BlocklistListings":  blListings,
		"BlocklistLastCheck": blLastChecked,
		"BlocklistEvents":    blEvents,
	})
}

func (a *Admin) listEmails(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domainID, _ := strconv.ParseInt(q.Get("domain"), 10, 64)
	win := resolveEmailWindow(q, time.Now().UTC())
	f := store.EmailFilter{
		Status:      q.Get("status"),
		Search:      q.Get("q"),
		DomainID:    domainID,
		CreatedFrom: win.CreatedFrom,
		CreatedTo:   win.CreatedTo,
	}
	const pageSize = 50
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	// Fetch one row beyond the page to learn whether a next page exists,
	// without a separate COUNT(*) query.
	f.Limit = pageSize + 1
	f.Offset = (page - 1) * pageSize
	emails, err := a.Store.ListEmails(f)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	hasNext := len(emails) > pageSize
	if hasNext {
		emails = emails[:pageSize]
	}
	// Links carry the *resolved* window (range plus, for a custom range, the
	// dates) rather than the raw query, so following one can never re-resolve
	// to a different period than the page it was rendered on.
	listURL := func(wd emailWindow, p int) string {
		v := url.Values{}
		if f.Status != "" {
			v.Set("status", f.Status)
		}
		if domainID != 0 {
			v.Set("domain", strconv.FormatInt(domainID, 10))
		}
		if f.Search != "" {
			v.Set("q", f.Search)
		}
		v.Set("range", wd.Range)
		if wd.FromDate != "" {
			v.Set("from", wd.FromDate)
		}
		if wd.ToDate != "" {
			v.Set("to", wd.ToDate)
		}
		v.Set("page", strconv.Itoa(p))
		return "/admin/emails?" + v.Encode()
	}
	pageURL := func(p int) string { return listURL(win, p) }
	// The period chips live outside the collapsible filter panel, so they're
	// links that keep the other filters rather than form controls.
	chips := make([]rangeChip, 0, len(emailRanges))
	for _, rg := range emailRanges {
		chips = append(chips, rangeChip{Key: rg.Key, Label: rg.Label, Title: rg.Title,
			URL: listURL(emailWindow{Range: rg.Key}, 1), Active: rg.Key == win.Range})
	}
	var prevURL, nextURL string
	if page > 1 {
		prevURL = pageURL(page - 1)
	}
	if hasNext {
		nextURL = pageURL(page + 1)
	}
	domains, _ := a.Store.ListDomains()
	// The panel opens when it holds state worth seeing: the non-period filters,
	// or the dates behind a custom period (the chips show the period itself).
	filtersActive := f.Status != "" || f.Search != "" || domainID != 0 || win.Range == "custom"
	a.render(w, r, "emails", map[string]any{
		"Emails": emails, "Domains": domains,
		"Status": f.Status, "Query": f.Search, "DomainID": domainID,
		"From": win.FromDate, "To": win.ToDate,
		"Ranges": chips, "RangeKey": win.Range, "WindowLabel": win.Label,
		"FiltersActive": filtersActive,
		"FilterState":   filterState(f.Status, f.Search, domainID, domains),
		"AllTimeURL":    listURL(emailWindow{Range: "all"}, 1),
		"Page":          page, "PrevURL": prevURL, "NextURL": nextURL,
		"CurrentURL": pageURL(page),
	})
}

// dmarcPage shows per-domain DMARC pass/fail rollups, the top failing
// sources, and the raw report list for a period. It reuses the same
// resolveEmailWindow + period-chip machinery as listEmails: this page has no
// other filters, so each chip link is just the range key against
// /admin/dmarc.
func (a *Admin) dmarcPage(w http.ResponseWriter, r *http.Request) {
	win := resolveEmailWindow(r.URL.Query(), time.Now().UTC())
	summary, err := a.Store.DMARCSummary(win.CreatedFrom, win.CreatedTo)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	sources, _ := a.Store.DMARCTopFailingSources(win.CreatedFrom, win.CreatedTo, 10)
	reports, _ := a.Store.ListDMARCReports(win.CreatedFrom, win.CreatedTo, 100)

	// Same chip semantics as the email list (admin.go ~476): each chip is a
	// plain link carrying only its range key, so clicking one clears any
	// custom dates. This page has no other filters, so the URL is just the key.
	chips := make([]rangeChip, 0, len(emailRanges))
	for _, rg := range emailRanges {
		chips = append(chips, rangeChip{Key: rg.Key, Label: rg.Label, Title: rg.Title,
			URL: "/admin/dmarc?range=" + rg.Key, Active: win.Range == rg.Key})
	}
	a.render(w, r, "dmarc", map[string]any{
		"Ranges": chips, "RangeKey": win.Range, "WindowLabel": win.Label,
		"Summary": summary, "Sources": sources, "Reports": reports,
	})
}

// retryable and cancelable mirror the store's status guards so the email page
// only offers the actions the store would accept. The store's conditional
// UPDATE remains the authority — it's what closes the read-then-write race
// against the delivery worker — but checking here keeps an obviously-wrong
// POST (retry a sent email, cancel a failed one) from reaching the DB and lets
// the response say which status blocked it.
func retryable(status string) bool {
	switch status {
	case "queued", "failed", "canceled":
		return true
	}
	return false
}

func cancelable(status string) bool { return status == "queued" }

// attachmentView is store.AttachmentMeta plus the size as the detail page
// shows it. The admin templates are parsed without a FuncMap, so anything a
// template can't express as a field access is formatted here in Go.
type attachmentView struct {
	store.AttachmentMeta
	SizeText string
}

// humanSize renders a byte count the way the size of an attachment is
// normally talked about — the point on the page is "is this the 4MB PDF I
// meant to send", not the exact octet count. Binary units, since that's what
// the byte limits in internal/send are expressed in.
func humanSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func (a *Admin) showEmail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	e, err := a.Store.GetEmail(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	attempts, _ := a.Store.ListAttempts(id)
	domain, _ := a.Store.GetDomain(e.DomainID)
	// Metadata only, never the bytes: the page needs to show what is attached
	// (a missing or unexpected attachment is exactly what you come here to
	// check after a "message too large" bounce), and pulling megabytes of BLOB
	// through to render a filename would be wasteful. There is deliberately no
	// download route — serving caller-supplied bytes from the admin origin is
	// new attack surface for a debugging convenience.
	var attachments []attachmentView
	if e.AttachmentCount > 0 {
		metas, _ := a.Store.ListAttachmentMeta(id)
		attachments = make([]attachmentView, len(metas))
		for i, m := range metas {
			attachments[i] = attachmentView{AttachmentMeta: m, SizeText: humanSize(m.Size)}
		}
	}
	a.render(w, r, "email", map[string]any{"Email": e, "Attempts": attempts, "Domain": domain,
		"Attachments": attachments,
		"CanRetry":    retryable(e.Status), "CanCancel": cancelable(e.Status),
		// The recipient input is pre-filled with the same "Name <addr>" form the
		// outgoing To header uses, so an unchanged submit round-trips the display
		// name instead of dropping it.
		"Recipient": delivery.FormatAddress(e.ToName, e.To)})
}

func (a *Admin) retryEmail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	e, err := a.Store.GetEmail(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !retryable(e.Status) {
		http.Error(w, "a "+e.Status+" email cannot be retried", 409)
		return
	}
	// The submitted recipient is split into routing address + display name:
	// to_addr must stay a bare address (it drives MX routing and the SMTP
	// envelope), so a pasted "Name <addr>" never lands there whole.
	var newTo, newToName string
	if v := strings.TrimSpace(r.FormValue("to")); v != "" {
		addr, err := mail.ParseAddress(v)
		if err != nil {
			http.Error(w, "invalid address", 422)
			return
		}
		if addr.Address != e.To || addr.Name != e.ToName {
			newTo, newToName = addr.Address, addr.Name
		}
	}
	if err := a.Store.RequeueEmail(id, newTo, newToName); err != nil {
		a.emailActionError(w, err, store.ErrNotRequeueable, "retried")
		return
	}
	http.Redirect(w, r, "/admin/emails/"+r.PathValue("id"), http.StatusSeeOther)
}

func (a *Admin) cancelEmail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	e, err := a.Store.GetEmail(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if !cancelable(e.Status) {
		http.Error(w, "only a queued email can be canceled; this one is "+e.Status, 409)
		return
	}
	if err := a.Store.CancelEmail(id); err != nil {
		a.emailActionError(w, err, store.ErrNotCancelable, "canceled")
		return
	}
	http.Redirect(w, r, "/admin/emails/"+r.PathValue("id"), http.StatusSeeOther)
}

// emailActionError turns a store status-guard rejection into a 409 the operator
// can act on: reaching it after the handler's own status check passed means a
// worker claimed the email in the meantime, and trying again shortly will work.
func (a *Admin) emailActionError(w http.ResponseWriter, err, guard error, verb string) {
	if errors.Is(err, guard) {
		http.Error(w, "the email was picked up for delivery a moment ago and cannot be "+
			verb+" while it is sending; try again shortly", 409)
		return
	}
	http.Error(w, err.Error(), 500)
}

func (a *Admin) listDomains(w http.ResponseWriter, r *http.Request) {
	domains, _ := a.Store.ListDomains()
	a.render(w, r, "domains", map[string]any{"Domains": domains})
}

func (a *Admin) createDomain(w http.ResponseWriter, r *http.Request) {
	d, err := domains.Create(a.Store, r.FormValue("name"))
	if errors.Is(err, domains.ErrInvalidName) {
		http.Error(w, "invalid domain name", 422)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/domains/%d", d.ID), http.StatusSeeOther)
}

func (a *Admin) showDomain(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := a.Store.GetDomain(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	pubB64, err := dkimkeys.PublicB64FromPrivatePEM(d.DKIMPrivateKey)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	records := dkimkeys.Records(d.Name, d.DKIMSelector, pubB64, a.EgressIP, a.DMARCRua)
	if d.Name == a.SystemDomain {
		records = append(records, dkimkeys.SystemRecords(a.SystemDomain, a.Hostname)...)
	}
	a.render(w, r, "domain", map[string]any{"Domain": d, "Records": records})
}

func (a *Admin) verifyDomain(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := a.Store.GetDomain(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if a.CheckDomain == nil {
		http.Error(w, "verification not configured", http.StatusInternalServerError)
		return
	}
	// domains.Verify owns the indeterminate-result guard (never persist a
	// transient resolver failure); the admin page redirects back regardless
	// of outcome, matching prior behavior.
	domains.Verify(r.Context(), a.Store, a.CheckDomain, d)
	http.Redirect(w, r, fmt.Sprintf("/admin/domains/%d", d.ID), http.StatusSeeOther)
}

// setDomainProvider switches a domain between direct delivery and a provider's
// API. The key field is write-only: the page never renders the stored key, and
// leaving the field empty keeps it (see domains.SetProvider).
func (a *Admin) setDomainProvider(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := a.Store.GetDomain(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	err = domains.SetProvider(a.Store, d, r.FormValue("provider"), r.FormValue("api_key"))
	switch {
	case errors.Is(err, domains.ErrInvalidProvider):
		http.Error(w, "unknown delivery provider", 422)
		return
	case errors.Is(err, domains.ErrProviderKey):
		http.Error(w, "a valid email.eu sending key is required to send via email.eu", 422)
		return
	case err != nil:
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/domains/%d", d.ID), http.StatusSeeOther)
}

func (a *Admin) listKeys(w http.ResponseWriter, r *http.Request) {
	a.renderKeys(w, r, "")
}

func (a *Admin) renderKeys(w http.ResponseWriter, r *http.Request, newToken string) {
	keys, _ := a.Store.ListAPIKeys()
	domains, _ := a.Store.ListDomains()
	byID := map[int64]string{}
	for _, d := range domains {
		byID[d.ID] = d.Name
	}
	a.render(w, r, "keys", map[string]any{"Keys": keys, "Domains": domains, "DomainNames": byID, "NewToken": newToken})
}

func (a *Admin) createKey(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	domainID, _ := strconv.ParseInt(r.FormValue("domain_id"), 10, 64)
	d, err := a.Store.GetDomain(domainID)
	if name == "" || err != nil {
		http.Error(w, "name and domain are required", 422)
		return
	}
	token, hash, err := store.GenerateAPIKey()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if _, err := a.Store.CreateAPIKey(name, domainID, hash); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if a.OnKeyCreated != nil {
		a.OnKeyCreated(name, d.Name)
	}
	a.renderKeys(w, r, token) // shown exactly once
}

func (a *Admin) revokeKey(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	keys, _ := a.Store.ListAPIKeys()
	var name, domainName string
	for _, k := range keys {
		if k.ID == id {
			name = k.Name
			if d, err := a.Store.GetDomain(k.DomainID); err == nil {
				domainName = d.Name
			}
		}
	}
	if err := a.Store.RevokeAPIKey(id); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if a.OnKeyRevoked != nil {
		a.OnKeyRevoked(name, domainName)
	}
	http.Redirect(w, r, "/admin/keys", http.StatusSeeOther)
}
