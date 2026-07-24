package admin

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"doevoe/internal/store"
	"doevoe/internal/webhook"
)

// eventOption is one checkbox on the webhook form.
type eventOption struct {
	Name, Help string
	Checked    bool
}

// eventOptions renders the event catalogue with the given selection ticked.
func eventOptions(selected []string) []eventOption {
	on := map[string]bool{}
	for _, e := range selected {
		on[e] = true
	}
	out := make([]eventOption, 0, len(webhook.Events))
	for _, e := range webhook.Events {
		out = append(out, eventOption{Name: e, Help: webhook.EventHelp[e], Checked: on[e]})
	}
	return out
}

func (a *Admin) listWebhooks(w http.ResponseWriter, r *http.Request) {
	hooks, err := a.Store.ListWebhooks()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	domains, _ := a.Store.ListDomains()
	names := map[int64]string{}
	for _, d := range domains {
		names[d.ID] = d.Name
	}
	a.render(w, r, "webhooks", map[string]any{
		"Webhooks": hooks, "Events": eventOptions(nil),
		"Domains": domains, "DomainNames": names,
	})
}

// webhookFields is what a create or update POST configures.
type webhookFields struct {
	Name, URL string
	// DomainID is 0 when the form's domain select is left on "all domains".
	DomainID int64
	Events   []string
}

// webhookForm pulls the shared fields off a create or update POST, writing the
// 422 itself when something doesn't validate.
func (a *Admin) webhookForm(w http.ResponseWriter, r *http.Request) (f webhookFields, ok bool) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 422)
		return f, false
	}
	f.Name = strings.TrimSpace(r.FormValue("name"))
	f.URL = strings.TrimSpace(r.FormValue("url"))
	if f.Name == "" {
		http.Error(w, "name is required", 422)
		return f, false
	}
	if err := webhook.ValidateURL(f.URL); err != nil {
		http.Error(w, "invalid url: "+err.Error(), 422)
		return f, false
	}
	// An unparseable domain_id is a rejection, not a silent fall back to "all
	// domains": scoping too widely leaks one tenant's events to another.
	if v := strings.TrimSpace(r.FormValue("domain_id")); v != "" && v != "0" {
		id, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "invalid domain", 422)
			return f, false
		}
		if _, err := a.Store.GetDomain(id); err != nil {
			http.Error(w, "unknown domain", 422)
			return f, false
		}
		f.DomainID = id
	}
	events, unknown := webhook.NormalizeEvents(r.Form["events"])
	if unknown != "" {
		http.Error(w, "unknown event: "+unknown, 422)
		return f, false
	}
	// A webhook subscribed to nothing would sit there looking configured and
	// never fire; make that a validation error rather than a silent no-op.
	if len(events) == 0 {
		http.Error(w, "select at least one event", 422)
		return f, false
	}
	f.Events = events
	return f, true
}

func (a *Admin) createWebhook(w http.ResponseWriter, r *http.Request) {
	f, ok := a.webhookForm(w, r)
	if !ok {
		return
	}
	secret, err := store.GenerateWebhookSecret()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	hook, err := a.Store.CreateWebhook(f.Name, f.URL, secret, f.DomainID, f.Events)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/webhooks/%d", hook.ID), http.StatusSeeOther)
}

func (a *Admin) showWebhook(w http.ResponseWriter, r *http.Request) {
	hook, err := a.webhookByPath(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	deliveries, err := a.Store.ListWebhookDeliveries(hook.ID, 25)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	domains, _ := a.Store.ListDomains()
	var scope string
	if !hook.AllDomains() {
		if d, err := a.Store.GetDomain(hook.DomainID); err == nil {
			scope = d.Name
		}
	}
	a.render(w, r, "webhook", map[string]any{
		"Webhook": hook, "Events": eventOptions(hook.Events), "Deliveries": deliveries,
		"Domains": domains, "Scope": scope,
	})
}

func (a *Admin) updateWebhook(w http.ResponseWriter, r *http.Request) {
	hook, err := a.webhookByPath(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, ok := a.webhookForm(w, r)
	if !ok {
		return
	}
	if err := a.Store.UpdateWebhook(hook.ID, f.Name, f.URL, f.DomainID, f.Events, r.FormValue("active") != ""); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/webhooks/%d", hook.ID), http.StatusSeeOther)
}

func (a *Admin) testWebhook(w http.ResponseWriter, r *http.Request) {
	hook, err := a.webhookByPath(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if a.OnWebhookTest == nil {
		http.Error(w, "webhook delivery not configured", http.StatusInternalServerError)
		return
	}
	if err := a.OnWebhookTest(hook.ID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("/admin/webhooks/%d", hook.ID), http.StatusSeeOther)
}

func (a *Admin) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	hook, err := a.webhookByPath(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := a.Store.DeleteWebhook(hook.ID); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.Redirect(w, r, "/admin/webhooks", http.StatusSeeOther)
}

func (a *Admin) webhookByPath(r *http.Request) (*store.Webhook, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		return nil, err
	}
	return a.Store.GetWebhook(id)
}
