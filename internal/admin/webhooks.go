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
	a.render(w, r, "webhooks", map[string]any{"Webhooks": hooks, "Events": eventOptions(nil)})
}

// webhookForm pulls the shared name/url/events fields off a create or update
// POST, writing the 422 itself when something doesn't validate.
func webhookForm(w http.ResponseWriter, r *http.Request) (name, url string, events []string, ok bool) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", 422)
		return "", "", nil, false
	}
	name = strings.TrimSpace(r.FormValue("name"))
	url = strings.TrimSpace(r.FormValue("url"))
	if name == "" {
		http.Error(w, "name is required", 422)
		return "", "", nil, false
	}
	if err := webhook.ValidateURL(url); err != nil {
		http.Error(w, "invalid url: "+err.Error(), 422)
		return "", "", nil, false
	}
	events, unknown := webhook.NormalizeEvents(r.Form["events"])
	if unknown != "" {
		http.Error(w, "unknown event: "+unknown, 422)
		return "", "", nil, false
	}
	// A webhook subscribed to nothing would sit there looking configured and
	// never fire; make that a validation error rather than a silent no-op.
	if len(events) == 0 {
		http.Error(w, "select at least one event", 422)
		return "", "", nil, false
	}
	return name, url, events, true
}

func (a *Admin) createWebhook(w http.ResponseWriter, r *http.Request) {
	name, url, events, ok := webhookForm(w, r)
	if !ok {
		return
	}
	secret, err := store.GenerateWebhookSecret()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	hook, err := a.Store.CreateWebhook(name, url, secret, events)
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
	a.render(w, r, "webhook", map[string]any{
		"Webhook": hook, "Events": eventOptions(hook.Events), "Deliveries": deliveries,
	})
}

func (a *Admin) updateWebhook(w http.ResponseWriter, r *http.Request) {
	hook, err := a.webhookByPath(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	name, url, events, ok := webhookForm(w, r)
	if !ok {
		return
	}
	if err := a.Store.UpdateWebhook(hook.ID, name, url, events, r.FormValue("active") != ""); err != nil {
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
