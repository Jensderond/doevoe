package dmarcreport

import (
	"strings"
	"testing"
	"time"
)

const googleShaped = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>12345678901234567890</report_id>
    <date_range><begin>1753999200</begin><end>1754085600</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>client.example</domain>
    <adkim>r</adkim><aspf>r</aspf><p>quarantine</p><sp>quarantine</sp><pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>203.0.113.7</source_ip>
      <count>11</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
    <identifiers><header_from>client.example</header_from></identifiers>
    <auth_results>
      <dkim><domain>client.example</domain><result>pass</result><selector>mail1</selector></dkim>
      <spf><domain>client.example</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.9</source_ip>
      <count>3</count>
      <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated>
    </row>
    <identifiers><header_from>client.example</header_from></identifiers>
  </record>
</feedback>`

func TestParseGoogleShaped(t *testing.T) {
	rep, err := Parse(strings.NewReader(googleShaped))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Org != "google.com" || rep.ReportID != "12345678901234567890" || rep.Domain != "client.example" {
		t.Errorf("metadata: %+v", rep)
	}
	if !rep.RangeBegin.Equal(time.Unix(1753999200, 0).UTC()) || !rep.RangeEnd.Equal(time.Unix(1754085600, 0).UTC()) {
		t.Errorf("range: %v .. %v", rep.RangeBegin, rep.RangeEnd)
	}
	if len(rep.Records) != 2 {
		t.Fatalf("records: %d, want 2", len(rep.Records))
	}
	r0, r1 := rep.Records[0], rep.Records[1]
	if r0.SourceIP != "203.0.113.7" || r0.Count != 11 || r0.Disposition != "none" ||
		r0.DKIM != "pass" || r0.SPF != "pass" || r0.HeaderFrom != "client.example" {
		t.Errorf("record 0: %+v", r0)
	}
	if r1.SourceIP != "198.51.100.9" || r1.Count != 3 || r1.DKIM != "fail" || r1.SPF != "fail" {
		t.Errorf("record 1: %+v", r1)
	}
}

func TestParseMissingOptionalFields(t *testing.T) {
	// No email, no disposition, no header_from: still a valid report.
	xml := `<feedback>
  <report_metadata><org_name>o</org_name><report_id>r1</report_id>
    <date_range><begin>1753999200</begin><end>1754085600</end></date_range></report_metadata>
  <policy_published><domain>d.example</domain></policy_published>
  <record><row><source_ip>192.0.2.1</source_ip><count>1</count>
    <policy_evaluated><dkim>fail</dkim><spf>pass</spf></policy_evaluated></row></record>
</feedback>`
	rep, err := Parse(strings.NewReader(xml))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Records[0].Disposition != "" || rep.Records[0].HeaderFrom != "" {
		t.Errorf("optional fields should default empty: %+v", rep.Records[0])
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	cases := map[string]string{
		"not xml":        "this is not xml at all {",
		"no org":         `<feedback><report_metadata><report_id>r</report_id></report_metadata><policy_published><domain>d</domain></policy_published><record><row><source_ip>1.2.3.4</source_ip><count>1</count></row></record></feedback>`,
		"no report id":   `<feedback><report_metadata><org_name>o</org_name></report_metadata><policy_published><domain>d</domain></policy_published><record><row><source_ip>1.2.3.4</source_ip><count>1</count></row></record></feedback>`,
		"no domain":      `<feedback><report_metadata><org_name>o</org_name><report_id>r</report_id></report_metadata><record><row><source_ip>1.2.3.4</source_ip><count>1</count></row></record></feedback>`,
		"zero records":   `<feedback><report_metadata><org_name>o</org_name><report_id>r</report_id></report_metadata><policy_published><domain>d</domain></policy_published></feedback>`,
		"negative count": `<feedback><report_metadata><org_name>o</org_name><report_id>r</report_id></report_metadata><policy_published><domain>d</domain></policy_published><record><row><source_ip>1.2.3.4</source_ip><count>-1</count></row></record></feedback>`,
	}
	for name, xml := range cases {
		if _, err := Parse(strings.NewReader(xml)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestParseWrongRoot(t *testing.T) {
	// Valid full document but wrong root element: must fail at decode level
	wrongRoot := `<not_feedback>
  <report_metadata>
    <org_name>test.org</org_name>
    <report_id>test-id-123</report_id>
    <date_range><begin>1753999200</begin><end>1754085600</end></date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
  </policy_published>
  <record>
    <row>
      <source_ip>192.0.2.1</source_ip>
      <count>5</count>
      <policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated>
    </row>
  </record>
</not_feedback>`
	_, err := Parse(strings.NewReader(wrongRoot))
	if err == nil {
		t.Fatalf("wrong root: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "expected element type") {
		t.Errorf("wrong root: expected 'expected element type' in error, got %v", err)
	}
}
