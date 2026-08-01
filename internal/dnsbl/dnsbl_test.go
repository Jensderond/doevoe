package dnsbl

import (
	"context"
	"net"
	"testing"
)

type fakeResolver struct {
	answers map[string][]string // query name -> A answers
	errs    map[string]error    // query name -> lookup error
}

func (f fakeResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	if err, ok := f.errs[host]; ok {
		return nil, err
	}
	if a, ok := f.answers[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// one status per (target, zone) pair, keyed for easy lookup
func byZone(t *testing.T, statuses []Status, target, zone string) Status {
	t.Helper()
	for _, st := range statuses {
		if st.Target == target && st.Zone == zone {
			return st
		}
	}
	t.Fatalf("no status for %s / %s in %+v", target, zone, statuses)
	return Status{}
}

func TestCheckVerdicts(t *testing.T) {
	r := fakeResolver{
		answers: map[string][]string{
			// egress IP 203.0.113.7 reversed = 7.113.0.203
			"7.113.0.203.zen.spamhaus.org":       {"127.0.0.2"},       // listed (SBL)
			"7.113.0.203.b.barracudacentral.org": {"127.255.255.254"}, // rate-limited -> indeterminate
			// bl.spamcop.net: no entry -> NXDOMAIN -> not listed
			"bad.example.dbl.spamhaus.org":    {"127.0.1.2"},   // domain listed
			"err.example.dbl.spamhaus.org":    {"127.0.1.255"}, // DBL error code -> indeterminate
			"wild.example.dbl.spamhaus.org":   {"216.58.1.1"},  // ISP wildcard DNS -> indeterminate
			"bad.example.multi.surbl.org":     {"127.0.0.8"},   // SURBL bitmask -> listed
		},
		errs: map[string]error{
			"err.example.multi.surbl.org": &net.DNSError{Err: "timeout", IsTimeout: true},
		},
	}
	statuses := Check(context.Background(), r, "203.0.113.7",
		[]string{"bad.example", "err.example", "wild.example"})

	// 3 IP zones for the egress IP + 2 domain zones x 3 domains = 9 statuses
	if len(statuses) != 9 {
		t.Fatalf("want 9 statuses, got %d: %+v", len(statuses), statuses)
	}
	cases := []struct {
		target, zone string
		want         Verdict
	}{
		{"203.0.113.7", "zen.spamhaus.org", Listed},
		{"203.0.113.7", "bl.spamcop.net", NotListed},
		{"203.0.113.7", "b.barracudacentral.org", Indeterminate},
		{"bad.example", "dbl.spamhaus.org", Listed},
		{"bad.example", "multi.surbl.org", Listed},
		{"err.example", "dbl.spamhaus.org", Indeterminate},
		{"err.example", "multi.surbl.org", Indeterminate},
		{"wild.example", "dbl.spamhaus.org", Indeterminate},
		{"wild.example", "multi.surbl.org", NotListed},
	}
	for _, c := range cases {
		if got := byZone(t, statuses, c.target, c.zone).Verdict; got != c.want {
			t.Errorf("%s / %s: verdict = %v, want %v", c.target, c.zone, got, c.want)
		}
	}
	if st := byZone(t, statuses, "203.0.113.7", "zen.spamhaus.org"); st.Response != "127.0.0.2" {
		t.Errorf("listed Response = %q, want the answering A record", st.Response)
	}
}

func TestCheckZenPBLCodeIsListed(t *testing.T) {
	// 127.0.0.10/11 are Spamhaus PBL ("policy: dynamic/residential IP") —
	// recipient servers reject on it, so it must count as listed.
	r := fakeResolver{answers: map[string][]string{
		"7.113.0.203.zen.spamhaus.org": {"127.0.0.10"},
	}}
	statuses := Check(context.Background(), r, "203.0.113.7", nil)
	if got := byZone(t, statuses, "203.0.113.7", "zen.spamhaus.org").Verdict; got != Listed {
		t.Errorf("PBL code: verdict = %v, want Listed", got)
	}
}

func TestCheckBadEgressIPIsIndeterminate(t *testing.T) {
	statuses := Check(context.Background(), fakeResolver{}, "not-an-ip", nil)
	if len(statuses) != 3 {
		t.Fatalf("want 3 IP-zone statuses, got %d", len(statuses))
	}
	for _, st := range statuses {
		if st.Verdict != Indeterminate {
			t.Errorf("%s: verdict = %v, want Indeterminate", st.Zone, st.Verdict)
		}
	}
}
