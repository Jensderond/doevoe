package dnscheck

import (
	"context"
	"errors"
	"net"
	"testing"
)

type fakeResolver map[string][]string

// LookupTXT reports a genuine "no such record" the way a real resolver
// does: a *net.DNSError with IsNotFound set. This matters now that dnscheck
// distinguishes absence from transport failure - a generic error here would
// be (mis)classified as Indeterminate instead of "record missing".
func (f fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := f[name]; ok {
		return v, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// erroringResolver always fails every lookup with a transport-style error
// (not a not-found DNS error), simulating a resolver blip (timeout,
// SERVFAIL, network partition, ...).
type erroringResolver struct{ err error }

func (r erroringResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	return nil, r.err
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

// TestCheckTransportErrorIsIndeterminate covers the critical fail-closed
// finding: a resolver blip (timeout, SERVFAIL, ...) must not be conflated
// with a genuinely absent record. Callers rely on Indeterminate=true here to
// know they must not persist this result as a real re-check.
func TestCheckTransportErrorIsIndeterminate(t *testing.T) {
	r := erroringResolver{err: errors.New("i/o timeout")}
	res := Check(context.Background(), r, "example.com", "mail1", "ABCDEF", "203.0.113.7")
	if !res.Indeterminate {
		t.Fatalf("want Indeterminate=true on a transport error: %+v", res)
	}
}

// TestCheckNotFoundIsNotIndeterminate is the counterpart: a record that is
// genuinely absent (net.DNSError with IsNotFound) is a normal, determinate
// "missing" result, not an indeterminate one.
func TestCheckNotFoundIsNotIndeterminate(t *testing.T) {
	r := fakeResolver{} // no records configured -> NotFound for every lookup
	res := Check(context.Background(), r, "example.com", "mail1", "ABCDEF", "203.0.113.7")
	if res.Indeterminate {
		t.Fatalf("want Indeterminate=false when records are merely absent: %+v", res)
	}
	if res.SPF.OK || res.DKIM.OK || res.DMARC.OK {
		t.Fatalf("want all not-OK: %+v", res)
	}
}
