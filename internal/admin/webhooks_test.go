package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"doevoe/internal/store"
	"doevoe/internal/webhook"
)

func TestCreateWebhook(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")

	resp, err := c.PostForm(srv.URL+"/admin/webhooks", url.Values{
		"name": {"site-a"}, "url": {"https://recv.test/hooks/doevoe"},
		"events": {webhook.EventEmailSent, webhook.EventEmailFailed},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, readBody(t, resp))
	}
	hooks, err := s.ListWebhooks()
	if err != nil || len(hooks) != 1 {
		t.Fatalf("hooks = %+v, %v", hooks, err)
	}
	h := hooks[0]
	if h.Name != "site-a" || h.URL != "https://recv.test/hooks/doevoe" || !h.Active {
		t.Fatalf("webhook = %+v", h)
	}
	if len(h.Events) != 2 {
		t.Fatalf("events = %v", h.Events)
	}
	if !strings.HasPrefix(h.Secret, "whsec_") {
		t.Errorf("secret = %q, want a generated whsec_ secret", h.Secret)
	}
	if got := resp.Header.Get("Location"); got != fmt.Sprintf("/admin/webhooks/%d", h.ID) {
		t.Errorf("Location = %q, want the new webhook's page", got)
	}
}

func TestCreateWebhookValidation(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")

	cases := []struct {
		name string
		form url.Values
	}{
		{"no name", url.Values{"url": {"https://recv.test/h"}, "events": {webhook.EventEmailSent}}},
		{"no events", url.Values{"name": {"x"}, "url": {"https://recv.test/h"}}},
		{"unknown event", url.Values{"name": {"x"}, "url": {"https://recv.test/h"}, "events": {"email.opened"}}},
		{"relative url", url.Values{"name": {"x"}, "url": {"/hooks"}, "events": {webhook.EventEmailSent}}},
		{"non-http url", url.Values{"name": {"x"}, "url": {"file:///etc/passwd"}, "events": {webhook.EventEmailSent}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := c.PostForm(srv.URL+"/admin/webhooks", tc.form)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 422 {
				t.Fatalf("status = %d, want 422 (body: %s)", resp.StatusCode, readBody(t, resp))
			}
		})
	}
	if hooks, _ := s.ListWebhooks(); len(hooks) != 0 {
		t.Fatalf("invalid submissions must not create webhooks, got %+v", hooks)
	}
}

func TestWebhooksListAndDetail(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	h, err := s.CreateWebhook("site-a", "https://recv.test/h", "whsec_shown", []string{webhook.EventEmailFailed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueWebhookDelivery(&store.WebhookDelivery{
		WebhookID: h.ID, Event: webhook.EventEmailFailed, Payload: `{"event":"email.failed"}`,
	}); err != nil {
		t.Fatal(err)
	}

	resp, _ := c.Get(srv.URL + "/admin/webhooks")
	body := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	for _, want := range []string{"site-a", "https://recv.test/h", `href="/admin/webhooks/` + fmt.Sprint(h.ID)} {
		if !strings.Contains(body, want) {
			t.Errorf("list page missing %q", want)
		}
	}
	if !strings.Contains(body, `href="/admin/webhooks" class="active"`) {
		t.Error("list page should mark the Webhooks nav item active")
	}
	if strings.Contains(body, "whsec_shown") {
		t.Error("the signing secret must not appear on the list page")
	}

	resp, _ = c.Get(fmt.Sprintf("%s/admin/webhooks/%d", srv.URL, h.ID))
	body = readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("detail status = %d", resp.StatusCode)
	}
	for _, want := range []string{"whsec_shown", "X-Doevoe-Signature", webhook.EventEmailFailed, "Send test event"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail page missing %q", want)
		}
	}
	if !strings.Contains(body, `value="email.failed" checked`) {
		t.Error("detail page must tick the subscribed events")
	}
	if !strings.Contains(body, `{&#34;event&#34;:&#34;email.failed&#34;}`) {
		t.Error("detail page should show the queued delivery's payload")
	}
}

func TestWebhookDetailNotFound(t *testing.T) {
	_, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	resp, err := c.Get(srv.URL + "/admin/webhooks/999")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestUpdateWebhook(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	h, err := s.CreateWebhook("site-a", "https://recv.test/h", "whsec_keep", []string{webhook.EventEmailSent})
	if err != nil {
		t.Fatal(err)
	}

	// No "active" checkbox in the form means the endpoint is paused.
	resp, err := c.PostForm(fmt.Sprintf("%s/admin/webhooks/%d", srv.URL, h.ID), url.Values{
		"name": {"site-a prod"}, "url": {"https://recv.test/v2"}, "events": {webhook.EventDomainUnverified},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, readBody(t, resp))
	}
	got, _ := s.GetWebhook(h.ID)
	if got.Name != "site-a prod" || got.URL != "https://recv.test/v2" || got.Active {
		t.Fatalf("after update: %+v", got)
	}
	if len(got.Events) != 1 || got.Events[0] != webhook.EventDomainUnverified {
		t.Fatalf("events = %v", got.Events)
	}
	if got.Secret != "whsec_keep" {
		t.Error("updating settings must not rotate the signing secret")
	}

	resp, _ = c.PostForm(fmt.Sprintf("%s/admin/webhooks/%d", srv.URL, h.ID), url.Values{
		"name": {"site-a prod"}, "url": {"https://recv.test/v2"},
		"events": {webhook.EventEmailSent}, "active": {"1"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("re-activate status = %d", resp.StatusCode)
	}
	if got, _ := s.GetWebhook(h.ID); !got.Active {
		t.Error("the active checkbox must re-enable the endpoint")
	}
}

func TestTestWebhookCallsHook(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	h, err := s.CreateWebhook("site-a", "https://recv.test/h", "sec", []string{webhook.EventEmailSent})
	if err != nil {
		t.Fatal(err)
	}

	// No OnWebhookTest wired (the fixture leaves it nil): the button must
	// report a server error rather than pretending it queued something.
	resp, _ := c.PostForm(fmt.Sprintf("%s/admin/webhooks/%d/test", srv.URL, h.ID), url.Values{})
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status without a dispatcher = %d, want 500", resp.StatusCode)
	}

	var called int64
	a := New(s, "hunter2", "203.0.113.7", "ops@example.com", "mail.example.com")
	a.OnWebhookTest = func(id int64) error { called = id; return nil }
	mux := http.NewServeMux()
	a.Routes(mux)
	wired := httptest.NewServer(mux)
	t.Cleanup(wired.Close)
	wc := authedClient(t, a, wired)

	resp, err = wc.PostForm(fmt.Sprintf("%s/admin/webhooks/%d/test", wired.URL, h.ID), url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, readBody(t, resp))
	}
	if called != h.ID {
		t.Errorf("OnWebhookTest got webhook %d, want %d", called, h.ID)
	}
}

func TestDeleteWebhook(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	h, err := s.CreateWebhook("site-a", "https://recv.test/h", "sec", []string{webhook.EventEmailSent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnqueueWebhookDelivery(&store.WebhookDelivery{
		WebhookID: h.ID, Event: webhook.EventEmailSent, Payload: "{}",
	}); err != nil {
		t.Fatal(err)
	}

	resp, err := c.PostForm(fmt.Sprintf("%s/admin/webhooks/%d/delete", srv.URL, h.ID), url.Values{})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("status = %d, body = %s", resp.StatusCode, readBody(t, resp))
	}
	if hooks, _ := s.ListWebhooks(); len(hooks) != 0 {
		t.Fatalf("hooks after delete = %+v", hooks)
	}
}

func TestWebhookRoutesRequireAuth(t *testing.T) {
	s, srv, c := adminFixture(t) // never logs in
	h, err := s.CreateWebhook("site-a", "https://recv.test/h", "whsec_secret", []string{webhook.EventEmailSent})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/admin/webhooks",
		fmt.Sprintf("/admin/webhooks/%d", h.ID),
	} {
		resp, err := c.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("GET %s = %d, want a redirect to login", path, resp.StatusCode)
		}
		if strings.Contains(readBody(t, resp), "whsec_secret") {
			t.Errorf("GET %s leaked the signing secret while unauthenticated", path)
		}
	}
	resp, err := c.PostForm(srv.URL+"/admin/webhooks", url.Values{
		"name": {"x"}, "url": {"https://recv.test/h"}, "events": {webhook.EventEmailSent},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("unauthenticated POST = %d, want a redirect to login", resp.StatusCode)
	}
	if hooks, _ := s.ListWebhooks(); len(hooks) != 1 {
		t.Errorf("unauthenticated POST must not create a webhook, hooks = %d", len(hooks))
	}
}
