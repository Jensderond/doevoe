package admin

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"html/template"
	"io/fs"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

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

	mu       sync.Mutex
	sessions map[string]time.Time
}

func New(s *store.Store, password, egressIP, adminEmail, hostname string) *Admin {
	return &Admin{Store: s, Password: password, EgressIP: egressIP,
		AdminEmail: adminEmail, Hostname: hostname, sessions: map[string]time.Time{}}
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
	// Task 11–12 add: domains…, keys…
}

func (a *Admin) login(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.FormValue("password")), []byte(a.Password)) != 1 {
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

func (a *Admin) renderStatus(w http.ResponseWriter, status int, page string, data any) {
	tpl, err := template.ParseFS(assets, "templates/layout.html", "templates/"+page+".html")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := tpl.ExecuteTemplate(w, "layout", data); err != nil {
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

func (a *Admin) listEmails(w http.ResponseWriter, r *http.Request) {
	domainID, _ := strconv.ParseInt(r.URL.Query().Get("domain"), 10, 64)
	f := store.EmailFilter{
		Status:   r.URL.Query().Get("status"),
		Search:   r.URL.Query().Get("q"),
		DomainID: domainID,
	}
	emails, err := a.Store.ListEmails(f)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	domains, _ := a.Store.ListDomains()
	a.render(w, "emails", map[string]any{
		"Emails": emails, "Domains": domains,
		"Status": f.Status, "Query": f.Search, "DomainID": domainID,
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
	newTo := strings.TrimSpace(r.FormValue("to"))
	if newTo != "" {
		if _, err := mail.ParseAddress(newTo); err != nil {
			http.Error(w, "invalid address", 422)
			return
		}
		e, err := a.Store.GetEmail(id)
		if err != nil {
			http.NotFound(w, r)
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
