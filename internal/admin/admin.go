package admin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/mail"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/dnscheck"
	"doevoe/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

type Admin struct {
	Store                                    *store.Store
	Password, EgressIP, AdminEmail, Hostname string
	OnKeyCreated, OnKeyRevoked               func(name, domainName string)
	CheckDomain                              func(ctx context.Context, d *store.Domain) dnscheck.Result

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
		a.render(w, "login", map[string]any{})
	})
	mux.HandleFunc("POST /admin/login", a.login)
	mux.Handle("POST /admin/logout", a.auth(a.logout))
	mux.Handle("GET /admin/{$}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin/emails", http.StatusSeeOther)
	}))
	mux.Handle("GET /admin/emails", a.auth(a.listEmails))
	mux.Handle("GET /admin/emails/{id}", a.auth(a.showEmail))
	mux.Handle("POST /admin/emails/{id}/retry", a.auth(a.retryEmail))
	mux.Handle("GET /admin/domains", a.auth(a.listDomains))
	mux.Handle("POST /admin/domains", a.auth(a.createDomain))
	mux.Handle("GET /admin/domains/{id}", a.auth(a.showDomain))
	mux.Handle("POST /admin/domains/{id}/verify", a.auth(a.verifyDomain))
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
		a.renderStatus(w, http.StatusUnauthorized, "login", map[string]any{"Error": "Wrong password"})
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
	"emails": "emails", "email": "emails",
	"domains": "domains", "domain": "domains",
	"keys": "keys",
}

func (a *Admin) renderStatus(w http.ResponseWriter, status int, page string, data any) {
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
	if err := tpl.ExecuteTemplate(w, "layout", view); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func (a *Admin) render(w http.ResponseWriter, page string, data any) {
	a.renderStatus(w, http.StatusOK, page, data)
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

func (a *Admin) listEmails(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domainID, _ := strconv.ParseInt(q.Get("domain"), 10, 64)
	f := store.EmailFilter{
		Status:   q.Get("status"),
		Search:   q.Get("q"),
		DomainID: domainID,
	}
	var fromDate, toDate string
	if d, ok := parseFilterDate(q.Get("from")); ok {
		f.CreatedFrom = store.FmtTime(d)
		fromDate = q.Get("from")
	}
	if d, ok := parseFilterDate(q.Get("to")); ok {
		// CreatedTo is exclusive; bump to the next day so the picked
		// "to" date itself is included, as a human would expect.
		f.CreatedTo = store.FmtTime(d.AddDate(0, 0, 1))
		toDate = q.Get("to")
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
	pageURL := func(p int) string {
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
		if fromDate != "" {
			v.Set("from", fromDate)
		}
		if toDate != "" {
			v.Set("to", toDate)
		}
		v.Set("page", strconv.Itoa(p))
		return "/admin/emails?" + v.Encode()
	}
	var prevURL, nextURL string
	if page > 1 {
		prevURL = pageURL(page - 1)
	}
	if hasNext {
		nextURL = pageURL(page + 1)
	}
	domains, _ := a.Store.ListDomains()
	a.render(w, "emails", map[string]any{
		"Emails": emails, "Domains": domains,
		"Status": f.Status, "Query": f.Search, "DomainID": domainID,
		"From": fromDate, "To": toDate,
		"Page": page, "PrevURL": prevURL, "NextURL": nextURL,
		"CurrentURL": pageURL(page),
	})
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
	a.render(w, "email", map[string]any{"Email": e, "Attempts": attempts, "Domain": domain})
}

func (a *Admin) retryEmail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	e, err := a.Store.GetEmail(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if e.Status != "failed" {
		http.Error(w, "only failed emails can be retried", 409)
		return
	}
	newTo := strings.TrimSpace(r.FormValue("to"))
	if newTo != "" {
		if _, err := mail.ParseAddress(newTo); err != nil {
			http.Error(w, "invalid address", 422)
			return
		}
		if newTo == e.To {
			newTo = "" // unchanged: plain retry
		}
	}
	if err := a.Store.RequeueEmail(id, newTo); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/admin/emails/"+r.PathValue("id"), http.StatusSeeOther)
}

func (a *Admin) listDomains(w http.ResponseWriter, r *http.Request) {
	domains, _ := a.Store.ListDomains()
	a.render(w, "domains", map[string]any{"Domains": domains})
}

func (a *Admin) createDomain(w http.ResponseWriter, r *http.Request) {
	name := strings.ToLower(strings.TrimSpace(r.FormValue("name")))
	if name == "" || strings.ContainsAny(name, " /@") {
		http.Error(w, "invalid domain name", 422)
		return
	}
	priv, _, err := dkimkeys.Generate()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	d, err := a.Store.CreateDomain(name, "mail1", priv)
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
	records := dkimkeys.Records(d.Name, d.DKIMSelector, pubB64, a.EgressIP, a.AdminEmail)
	a.render(w, "domain", map[string]any{"Domain": d, "Records": records})
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
	res := a.CheckDomain(r.Context(), d)
	if res.Indeterminate {
		// A transient resolver failure, not a genuine "record missing"
		// answer: persisting this would flip an already-verified domain to
		// unverified (and fail-close its sends with 403) on a mere DNS
		// blip. Skip the write and just redirect back unchanged.
		slog.Warn("dns verification indeterminate; not persisting", "domain", d.Name)
	} else {
		a.Store.SetDomainVerification(d.ID, res.SPF.OK, res.DKIM.OK, res.DMARC.OK, store.Now())
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/domains/%d", d.ID), http.StatusSeeOther)
}

func (a *Admin) listKeys(w http.ResponseWriter, r *http.Request) {
	a.renderKeys(w, "")
}

func (a *Admin) renderKeys(w http.ResponseWriter, newToken string) {
	keys, _ := a.Store.ListAPIKeys()
	domains, _ := a.Store.ListDomains()
	byID := map[int64]string{}
	for _, d := range domains {
		byID[d.ID] = d.Name
	}
	a.render(w, "keys", map[string]any{"Keys": keys, "Domains": domains, "DomainNames": byID, "NewToken": newToken})
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
	a.renderKeys(w, token) // shown exactly once
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
