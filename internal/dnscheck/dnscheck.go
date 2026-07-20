package dnscheck

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode"
)

type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type RecordResult struct {
	OK              bool
	Found, Expected string
}

// Result is the outcome of checking a domain's SPF/DKIM/DMARC records.
//
// Indeterminate is true when at least one of the underlying TXT lookups
// failed with a transport-level error (timeout, SERVFAIL, network error,
// ...) rather than a genuine "no such record" answer. When Indeterminate is
// true, callers must not persist this result (e.g. via
// store.SetDomainVerification): doing so would flip a previously-verified
// domain to unverified on a transient resolver blip, causing every send for
// that domain to fail closed with 403 until the next successful check.
type Result struct {
	SPF, DKIM, DMARC RecordResult
	Indeterminate    bool
}

func (r Result) AllOK() bool { return r.SPF.OK && r.DKIM.OK && r.DMARC.OK }

func Check(ctx context.Context, r Resolver, domain, selector, pubBase64, egressIP string) Result {
	var out Result

	out.SPF.Expected = fmt.Sprintf("v=spf1 ip4:%s -all", egressIP)
	spfTXT, err := lookup(ctx, r, domain)
	if err != nil {
		out.Indeterminate = true
	}
	for _, txt := range spfTXT {
		if strings.HasPrefix(txt, "v=spf1") {
			out.SPF.Found = txt
			if strings.Contains(txt, "ip4:"+egressIP) {
				out.SPF.OK = true
				break
			}
		}
	}

	out.DKIM.Expected = "p=" + pubBase64
	dkimTXTs, err := lookup(ctx, r, selector+"._domainkey."+domain)
	if err != nil {
		out.Indeterminate = true
	}
	dkimTxt := strings.Join(dkimTXTs, "")
	out.DKIM.Found = dkimTxt
	stripped := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, dkimTxt)
	out.DKIM.OK = strings.Contains(stripped, "p="+pubBase64)

	out.DMARC.Expected = "v=DMARC1; …"
	dmarcTXT, err := lookup(ctx, r, "_dmarc."+domain)
	if err != nil {
		out.Indeterminate = true
	}
	for _, txt := range dmarcTXT {
		if strings.HasPrefix(txt, "v=DMARC1") {
			out.DMARC.Found = txt
			out.DMARC.OK = true
		}
	}
	return out
}

// lookup performs a TXT lookup and distinguishes genuine absence of a
// record from a failed lookup. A *net.DNSError with IsNotFound (the
// standard shape for "no such record") is treated as absence and returns
// (nil, nil), matching historical behavior. Any other error (timeout,
// SERVFAIL, connection refused, ...) is returned to the caller so it can be
// treated as indeterminate rather than "record missing".
func lookup(ctx context.Context, r Resolver, name string) ([]string, error) {
	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, nil
		}
		return nil, err
	}
	return txts, nil
}
