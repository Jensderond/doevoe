// Package dnsbl checks whether the egress IP or a sending domain is listed
// on a fixed set of DNS blacklists. It mirrors internal/dnscheck's shape:
// pure functions over an injected Resolver so tests use a fake, and a
// three-way verdict that separates "definitely (not) listed" from "cannot
// tell right now".
package dnsbl

import (
	"context"
	"errors"
	"net"
	"strings"
)

// Resolver is the subset of *net.Resolver we need; net.DefaultResolver
// satisfies it.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

type Verdict int

const (
	// NotListed is the healthy answer: the zone returned NXDOMAIN.
	NotListed Verdict = iota
	// Listed means the zone answered inside its documented listing range.
	Listed
	// Indeterminate means the lookup failed or answered outside the zone's
	// listing range (Spamhaus public-resolver/rate-limit codes, ISP wildcard
	// DNS, timeouts). Callers must not persist or alert on Indeterminate:
	// Spamhaus deliberately refuses queries via public resolvers
	// (Google/Cloudflare DNS) with 127.255.255.x codes, so treating those as
	// "listed" would give every such install a permanent false alarm — the
	// same fail-open-on-transient rule as dnscheck.Result.Indeterminate.
	Indeterminate
)

// Status is the outcome of checking one target against one zone.
type Status struct {
	Target   string // the IP or domain that was checked
	Zone     string
	Verdict  Verdict
	Response string // first A answer when the zone answered; "" on NXDOMAIN/error
}

// zone describes one blacklist: its DNS suffix, whether it takes reversed
// IPs or domain names, and which 127.0.0.0/8 answers mean "listed".
// Everything else inside 127/8 (error/diagnostic codes) and everything
// outside it (wildcard resolvers) is Indeterminate.
type zone struct {
	name   string
	forIP  bool
	listed func(o [4]byte) bool // o = the answer's IPv4 octets
}

var zones = []zone{
	{"zen.spamhaus.org", true, func(o [4]byte) bool {
		return o[1] == 0 && o[2] == 0 && o[3] >= 2 && o[3] <= 11 // SBL/CSS/XBL/PBL
	}},
	{"bl.spamcop.net", true, func(o [4]byte) bool {
		return o[1] == 0 && o[2] == 0 && o[3] == 2
	}},
	{"b.barracudacentral.org", true, func(o [4]byte) bool {
		return o[1] == 0 && o[2] == 0 && o[3] == 2
	}},
	{"dbl.spamhaus.org", false, func(o [4]byte) bool {
		return o[1] == 0 && o[2] == 1 && o[3] < 255 // 127.0.1.255 = "IP queries prohibited" error
	}},
	{"multi.surbl.org", false, func(o [4]byte) bool {
		return o[1] == 0 && o[2] == 0 && o[3] >= 2 // bitmask of SURBL sub-lists
	}},
}

// Check queries every IP zone for egressIP and every domain zone for each
// domain, returning one Status per (target, zone) pair.
func Check(ctx context.Context, r Resolver, egressIP string, domains []string) []Status {
	var out []Status
	rev, revOK := reverseIPv4(egressIP)
	for _, z := range zones {
		if z.forIP {
			if !revOK {
				out = append(out, Status{Target: egressIP, Zone: z.name, Verdict: Indeterminate})
				continue
			}
			out = append(out, query(ctx, r, z, egressIP, rev+"."+z.name))
			continue
		}
		for _, d := range domains {
			out = append(out, query(ctx, r, z, d, d+"."+z.name))
		}
	}
	return out
}

func query(ctx context.Context, r Resolver, z zone, target, name string) Status {
	st := Status{Target: target, Zone: z.name}
	addrs, err := r.LookupHost(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			st.Verdict = NotListed // NXDOMAIN: the one genuinely healthy answer
			return st
		}
		st.Verdict = Indeterminate // timeout, SERVFAIL, network error, ...
		return st
	}
	if len(addrs) == 0 {
		st.Verdict = Indeterminate
		return st
	}
	st.Response = addrs[0]
	st.Verdict = classify(z, addrs)
	return st
}

func classify(z zone, addrs []string) Verdict {
	for _, a := range addrs {
		ip4 := net.ParseIP(a).To4()
		if ip4 == nil || ip4[0] != 127 {
			// Not a loopback answer: an intercepting/wildcard resolver, not
			// the blacklist speaking. Cannot conclude anything.
			return Indeterminate
		}
		if z.listed([4]byte(ip4)) {
			return Listed
		}
	}
	// Loopback answers outside the listing range: Spamhaus error codes
	// (127.255.255.x = public resolver / rate limited / blocked) and
	// anything undocumented. Never treat these as listed — see Indeterminate.
	return Indeterminate
}

// reverseIPv4 turns "203.0.113.7" into "7.113.0.203". ok is false for
// anything that is not a plain IPv4 address.
func reverseIPv4(s string) (string, bool) {
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return "", false
	}
	o := strings.Split(ip.To4().String(), ".")
	return o[3] + "." + o[2] + "." + o[1] + "." + o[0], true
}
