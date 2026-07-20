package admin

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"doevoe/internal/dnscheck"
)

func TestCreateDomainShowsWizard(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")

	resp, _ := c.PostForm(srv.URL+"/admin/domains", url.Values{"name": {"client.example"}})
	if resp.StatusCode != 303 {
		t.Fatalf("create: %d", resp.StatusCode)
	}
	d, _ := s.GetDomainByName("client.example")
	if d == nil || d.DKIMSelector != "mail1" || !strings.Contains(d.DKIMPrivateKey, "RSA PRIVATE KEY") {
		t.Fatalf("domain row: %+v", d)
	}
	resp, _ = c.Get(srv.URL + resp.Header.Get("Location"))
	body := readBody(t, resp)
	for _, want := range []string{"v=spf1 ip4:203.0.113.7 -all", "mail1._domainkey", "v=DMARC1", "PTR"} {
		if !strings.Contains(body, want) {
			t.Errorf("wizard missing %q", want)
		}
	}
}

func TestVerifyDomainUpdatesFlags(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	c.PostForm(srv.URL+"/admin/domains", url.Values{"name": {"client.example"}})
	d, _ := s.GetDomainByName("client.example")

	// adminFixture must set a.CheckDomain to this controllable fake:
	setFakeCheck(t, dnscheck.Result{
		SPF:   dnscheck.RecordResult{OK: true},
		DKIM:  dnscheck.RecordResult{OK: true},
		DMARC: dnscheck.RecordResult{OK: false, Found: ""},
	})
	c.PostForm(srv.URL+"/admin/domains/1/verify", nil)
	d, _ = s.GetDomain(d.ID)
	if !d.SPFVerified || !d.DKIMVerified || d.DMARCVerified || d.Verified() {
		t.Fatalf("flags: %+v", d)
	}
	_ = context.Background
}

func TestAPIKeyCreateShowsTokenOnce(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")
	c.PostForm(srv.URL+"/admin/domains", url.Values{"name": {"client.example"}})

	resp, _ := c.PostForm(srv.URL+"/admin/keys", url.Values{"name": {"site-a"}, "domain_id": {"1"}})
	body := readBody(t, resp)
	if !strings.Contains(body, "dv_") {
		t.Fatal("plaintext token must be shown once after creation")
	}
	keys, _ := s.ListAPIKeys()
	if len(keys) != 1 || keys[0].Name != "site-a" {
		t.Fatalf("keys: %+v", keys)
	}
	resp, _ = c.Get(srv.URL + "/admin/keys")
	if strings.Contains(readBody(t, resp), "dv_") {
		t.Fatal("token must not be shown on subsequent views")
	}
}
