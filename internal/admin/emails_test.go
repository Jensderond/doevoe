package admin

import (
	"net/url"
	"strings"
	"testing"

	"doevoe/internal/store"
)

func TestEmailsListAndFilter(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@gmial.com", Subject: "Welcome!", BodyText: "hi"})
	s.MarkFailed(id, "550 no such domain")

	resp, _ := c.Get(srv.URL + "/admin/emails?status=failed")
	body := readBody(t, resp)
	if !strings.Contains(body, "u@gmial.com") || !strings.Contains(body, "Welcome!") {
		t.Fatalf("failed email missing from list:\n%s", body)
	}
	resp, _ = c.Get(srv.URL + "/admin/emails?status=sent")
	if strings.Contains(readBody(t, resp), "u@gmial.com") {
		t.Fatal("status filter not applied")
	}
}

func TestEmailDetailShowsAttempts(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@dest.test", Subject: "s", BodyText: "b"})
	s.RecordAttempt(id, 1, 451, "mx1.dest.test", "451 greylisted, try later", 320)

	resp, _ := c.Get(srv.URL + "/admin/emails/1")
	body := readBody(t, resp)
	for _, want := range []string{"mx1.dest.test", "451 greylisted", "u@dest.test"} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q", want)
		}
	}
}

func TestRetryWithRecipientEdit(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@gmial.com", Subject: "s", BodyText: "b"})
	s.MarkFailed(id, "550")

	resp, err := c.PostForm(srv.URL+"/admin/emails/1/retry", url.Values{"to": {"u@gmail.com"}})
	if err != nil || resp.StatusCode != 303 {
		t.Fatalf("retry: %v %d", err, resp.StatusCode)
	}
	e, _ := s.GetEmail(id)
	if e.To != "u@gmail.com" || e.OriginalTo != "u@gmial.com" || e.Status != "queued" {
		t.Fatalf("after retry: %+v", e)
	}
}
