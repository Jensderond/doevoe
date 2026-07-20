package dnscheck

import (
	"context"
	"fmt"
	"strings"
)

type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
}

type RecordResult struct {
	OK              bool
	Found, Expected string
}

type Result struct{ SPF, DKIM, DMARC RecordResult }

func (r Result) AllOK() bool { return r.SPF.OK && r.DKIM.OK && r.DMARC.OK }

func Check(ctx context.Context, r Resolver, domain, selector, pubBase64, egressIP string) Result {
	var out Result

	out.SPF.Expected = fmt.Sprintf("v=spf1 ip4:%s -all", egressIP)
	for _, txt := range lookup(ctx, r, domain) {
		if strings.HasPrefix(txt, "v=spf1") {
			out.SPF.Found = txt
			out.SPF.OK = strings.Contains(txt, "ip4:"+egressIP)
		}
	}

	out.DKIM.Expected = "p=" + pubBase64
	dkimTxt := strings.Join(lookup(ctx, r, selector+"._domainkey."+domain), "")
	out.DKIM.Found = dkimTxt
	stripped := strings.NewReplacer(" ", "", "\t", "").Replace(dkimTxt)
	out.DKIM.OK = strings.Contains(stripped, "p="+pubBase64)

	out.DMARC.Expected = "v=DMARC1; …"
	for _, txt := range lookup(ctx, r, "_dmarc."+domain) {
		if strings.HasPrefix(txt, "v=DMARC1") {
			out.DMARC.Found = txt
			out.DMARC.OK = true
		}
	}
	return out
}

func lookup(ctx context.Context, r Resolver, name string) []string {
	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		return nil
	}
	return txts
}
