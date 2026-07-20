package admin

import (
	"net/url"
	"strconv"
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

func TestDomainFilter(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d1, _ := s.CreateDomain("example.com", "mail1", "PEM")
	d2, _ := s.CreateDomain("example.org", "mail2", "PEM")
	id1, _ := s.EnqueueEmail(&store.Email{DomainID: d1.ID, From: "a@example.com", To: "u1@dest.test", Subject: "s1", BodyText: "b"})
	id2, _ := s.EnqueueEmail(&store.Email{DomainID: d2.ID, From: "a@example.org", To: "u2@dest.test", Subject: "s2", BodyText: "b"})
	s.MarkFailed(id1, "550")
	s.MarkFailed(id2, "550")

	// Filter by first domain
	resp, _ := c.Get(srv.URL + "/admin/emails?domain=" + strconv.FormatInt(d1.ID, 10))
	body := readBody(t, resp)
	if !strings.Contains(body, "u1@dest.test") {
		t.Errorf("domain 1 email missing")
	}
	if strings.Contains(body, "u2@dest.test") {
		t.Errorf("domain 2 email should not be shown")
	}

	// Filter by second domain
	resp, _ = c.Get(srv.URL + "/admin/emails?domain=" + strconv.FormatInt(d2.ID, 10))
	body = readBody(t, resp)
	if !strings.Contains(body, "u2@dest.test") {
		t.Errorf("domain 2 email missing")
	}
	if strings.Contains(body, "u1@dest.test") {
		t.Errorf("domain 1 email should not be shown")
	}
}

func TestSearchEmails(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	_, _ = s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "alice@example.com", Subject: "Hello", BodyText: "b"})
	_, _ = s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "bob@example.com", Subject: "World", BodyText: "b"})

	// Search matching alice
	resp, _ := c.Get(srv.URL + "/admin/emails?q=alice")
	body := readBody(t, resp)
	if !strings.Contains(body, "alice@example.com") {
		t.Errorf("alice email missing from search results")
	}
	if strings.Contains(body, "bob@example.com") {
		t.Errorf("bob email should not be in alice search")
	}

	// Search non-matching
	resp, _ = c.Get(srv.URL + "/admin/emails?q=charlie")
	body = readBody(t, resp)
	if strings.Contains(body, "alice@example.com") || strings.Contains(body, "bob@example.com") {
		t.Errorf("non-matching search should show neither email")
	}
}

func TestPlainRetryUnchangedRecipient(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@example.com", Subject: "s", BodyText: "b"})
	s.MarkFailed(id, "550")

	resp, err := c.PostForm(srv.URL+"/admin/emails/"+strconv.FormatInt(id, 10)+"/retry", url.Values{"to": {"u@example.com"}})
	if err != nil || resp.StatusCode != 303 {
		t.Fatalf("plain retry: %v %d", err, resp.StatusCode)
	}
	e, _ := s.GetEmail(id)
	if e.Status != "queued" || e.OriginalTo != "" {
		t.Fatalf("after plain retry: status=%s, original_to=%q", e.Status, e.OriginalTo)
	}
}

func TestRetryInvalidAddress(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@example.com", Subject: "s", BodyText: "b"})
	s.MarkFailed(id, "550")

	resp, _ := c.PostForm(srv.URL+"/admin/emails/"+strconv.FormatInt(id, 10)+"/retry", url.Values{"to": {"not-an-address"}})
	if resp.StatusCode != 422 {
		t.Fatalf("invalid address should return 422, got %d", resp.StatusCode)
	}
	e, _ := s.GetEmail(id)
	if e.Status != "failed" {
		t.Fatalf("email should still be failed after invalid retry attempt")
	}
}

func TestRetryNotFound(t *testing.T) {
	_, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")

	resp, _ := c.PostForm(srv.URL+"/admin/emails/99999/retry", url.Values{})
	if resp.StatusCode != 404 {
		t.Fatalf("POST retry on missing email should return 404, got %d", resp.StatusCode)
	}
}

func TestRetryStatusGuard(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, _ := s.EnqueueEmail(&store.Email{DomainID: d.ID, From: "a@example.com", To: "u@example.com", Subject: "s", BodyText: "b"})
	s.MarkSent(id, "2024-01-01T00:00:00Z")

	resp, _ := c.PostForm(srv.URL+"/admin/emails/"+strconv.FormatInt(id, 10)+"/retry", url.Values{})
	if resp.StatusCode != 409 {
		t.Fatalf("retry on sent email should return 409, got %d", resp.StatusCode)
	}
	e, _ := s.GetEmail(id)
	if e.Status != "sent" {
		t.Fatalf("email should still be sent after failed retry attempt")
	}
}
