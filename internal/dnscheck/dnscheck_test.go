package dnscheck

import (
	"context"
	"errors"
	"testing"
)

type fakeResolver map[string][]string

func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f[name]; ok {
		return v, nil
	}
	return nil, errors.New("no such host")
}

func TestCheckAllVerified(t *testing.T) {
	r := fakeResolver{
		"example.com":                  {"v=spf1 ip4:203.0.113.7 -all"},
		"mail1._domainkey.example.com": {"v=DKIM1; k=rsa; p=ABC", "DEF"},
		"_dmarc.example.com":           {"v=DMARC1; p=quarantine; rua=mailto:ops@example.com"},
	}
	res := Check(context.Background(), r, "example.com", "mail1", "ABCDEF", "203.0.113.7")
	if !res.SPF.OK || !res.DKIM.OK || !res.DMARC.OK || !res.AllOK() {
		t.Fatalf("want all OK: %+v", res)
	}
}

func TestCheckMissingAndWrong(t *testing.T) {
	r := fakeResolver{
		"example.com": {"v=spf1 ip4:198.51.100.1 -all"}, // wrong IP
	}
	res := Check(context.Background(), r, "example.com", "mail1", "ABCDEF", "203.0.113.7")
	if res.SPF.OK || res.DKIM.OK || res.DMARC.OK {
		t.Fatalf("want all not-OK: %+v", res)
	}
	if res.SPF.Found == "" {
		t.Error("SPF.Found should carry what was found for the admin diff view")
	}
}

func TestCheckMultipleSPFRecords(t *testing.T) {
	// Test that first matching SPF record wins, even if later records don't match
	r := fakeResolver{
		"example.com": {
			"v=spf1 ip4:203.0.113.7 -all",  // first record, matches
			"v=spf1 ip4:198.51.100.1 -all", // second record, doesn't match
		},
	}
	res := Check(context.Background(), r, "example.com", "mail1", "ABCDEF", "203.0.113.7")
	if !res.SPF.OK {
		t.Fatalf("want SPF.OK=true when first record matches: %+v", res)
	}
	if res.SPF.Found != "v=spf1 ip4:203.0.113.7 -all" {
		t.Errorf("want SPF.Found to be first matching record, got %q", res.SPF.Found)
	}
}
