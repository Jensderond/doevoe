// Package dmarcreport parses RFC 7489 DMARC aggregate reports: extracting
// the XML payload from the report email (extract.go) and unmarshalling the
// aggregate-report schema (parse.go). It is pure — no store or network
// dependencies — so the whole ingestion path is testable without SMTP.
package dmarcreport

import (
	"encoding/xml"
	"fmt"
	"io"
	"time"
)

// Report is one parsed aggregate report.
type Report struct {
	Org, Email, ReportID, Domain string
	RangeBegin, RangeEnd         time.Time
	Records                      []Record
}

// Record is one <record> row: what one source IP did during the range.
type Record struct {
	SourceIP                           string
	Count                              int
	Disposition, DKIM, SPF, HeaderFrom string
}

// feedback mirrors the RFC 7489 Appendix C schema, limited to the fields we
// store. Unknown elements (auth_results, pct, adkim, ...) are ignored by
// encoding/xml, which is what makes reports from different providers parse.
type feedback struct {
	XMLName        xml.Name `xml:"feedback"`
	ReportMetadata struct {
		OrgName   string `xml:"org_name"`
		Email     string `xml:"email"`
		ReportID  string `xml:"report_id"`
		DateRange struct {
			Begin int64 `xml:"begin"`
			End   int64 `xml:"end"`
		} `xml:"date_range"`
	} `xml:"report_metadata"`
	PolicyPublished struct {
		Domain string `xml:"domain"`
	} `xml:"policy_published"`
	Records []struct {
		Row struct {
			SourceIP        string `xml:"source_ip"`
			Count           int    `xml:"count"`
			PolicyEvaluated struct {
				Disposition string `xml:"disposition"`
				DKIM        string `xml:"dkim"`
				SPF         string `xml:"spf"`
			} `xml:"policy_evaluated"`
		} `xml:"row"`
		Identifiers struct {
			HeaderFrom string `xml:"header_from"`
		} `xml:"identifiers"`
	} `xml:"record"`
}

// Parse unmarshals one aggregate report. It validates the fields the store
// depends on (org + report_id form the dedup key; domain and at least one
// record make the report meaningful) and rejects anything else as malformed.
func Parse(r io.Reader) (*Report, error) {
	var f feedback
	dec := xml.NewDecoder(r)
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("dmarc xml: %w", err)
	}
	if f.ReportMetadata.OrgName == "" {
		return nil, fmt.Errorf("dmarc xml: missing org_name")
	}
	if f.ReportMetadata.ReportID == "" {
		return nil, fmt.Errorf("dmarc xml: missing report_id")
	}
	if f.PolicyPublished.Domain == "" {
		return nil, fmt.Errorf("dmarc xml: missing policy_published domain")
	}
	if len(f.Records) == 0 {
		return nil, fmt.Errorf("dmarc xml: no records")
	}
	for _, rec := range f.Records {
		if rec.Row.Count < 0 {
			return nil, fmt.Errorf("dmarc xml: negative count")
		}
	}
	rep := &Report{
		Org: f.ReportMetadata.OrgName, Email: f.ReportMetadata.Email,
		ReportID: f.ReportMetadata.ReportID, Domain: f.PolicyPublished.Domain,
		RangeBegin: time.Unix(f.ReportMetadata.DateRange.Begin, 0).UTC(),
		RangeEnd:   time.Unix(f.ReportMetadata.DateRange.End, 0).UTC(),
	}
	for _, rec := range f.Records {
		rep.Records = append(rep.Records, Record{
			SourceIP: rec.Row.SourceIP, Count: rec.Row.Count,
			Disposition: rec.Row.PolicyEvaluated.Disposition,
			DKIM:        rec.Row.PolicyEvaluated.DKIM,
			SPF:         rec.Row.PolicyEvaluated.SPF,
			HeaderFrom:  rec.Identifiers.HeaderFrom,
		})
	}
	return rep, nil
}
