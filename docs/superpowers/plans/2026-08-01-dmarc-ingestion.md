# DMARC Report Ingestion Implementation Plan (Phase 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** doevoe receives DMARC aggregate reports over SMTP, parses and stores them, shows per-domain rollups on a new admin page, and alerts the admin when our own egress IP fails DMARC.

**Architecture:** A go-smtp **server** (`internal/inbound`) accepts mail only for `dmarc@<system-domain>`; a pure parser package (`internal/dmarcreport`) extracts the gzip/zip/xml attachment from the MIME message and parses the RFC 7489 aggregate-report XML; two new store tables hold reports (deduped on org+report_id) and per-source records; `/admin/dmarc` renders windowed rollups reusing the email list's `emailWindow` machinery; `notify.DMARCFailure` emails the admin with a 24h per-domain cooldown via `notify_state`. All recommended DMARC records switch their `rua=` to the report address, and the system domain gains an MX record plus the RFC 7489 §7.1 wildcard authorization record.

**Tech Stack:** Go stdlib (`encoding/xml`, `compress/gzip`, `archive/zip`, `mime`, `mime/multipart`, `net/mail`, `encoding/base64`) + `github.com/emersion/go-smtp` v0.24 (already a dependency — its server side). No new module dependencies.

**Spec:** `docs/superpowers/specs/2026-08-01-dmarc-dnsbl-monitoring-design.md` (Phase 2 sections). Phase 1 (DNSBL monitoring) is already on this branch.

## Global Constraints

- No new Go module dependencies (`go.mod` must not change).
- `go vet ./...` and `go test ./...` must pass after every task (this is CI).
- Timestamps are RFC3339 strings via `store.Now()` / `store.FmtTime()` — never SQLite time types.
- The store runs with `db.SetMaxOpenConns(1)`. Inside a transaction, every statement MUST go through the `tx` handle — an `s.db.Query` while a tx is open deadlocks.
- New tables go into the `schema` constant with `CREATE TABLE IF NOT EXISTS` only; no `migrate()` entry (those are for new columns on existing tables).
- **The inbound listener is not a mail server:** it must reject (550) every RCPT except exactly the report address, never relay, and require no auth.
- **Malformed, oversized-after-decompression, or duplicate reports are accepted at the SMTP level (250) and logged, never 5xx'd** — rejecting only makes the reporter retry a message we will never parse. Transient store errors return 451 so the reporter retries later.
- Decompression is capped (`maxXMLBytes = 50 << 20` decompressed) — decompression-bomb guard. Message size capped at 15 MB via go-smtp's `MaxMessageBytes`.
- Notifications are fail-open (existing `enqueue` semantics); a notification failure never blocks report storage.
- Money-quote invariants get comments next to the code they constrain (project convention).

---

### Task 1: `internal/dmarcreport` — aggregate-report XML parser

**Files:**
- Create: `internal/dmarcreport/parse.go`
- Test: `internal/dmarcreport/parse_test.go`

**Interfaces:**
- Consumes: nothing from this codebase.
- Produces (used by Tasks 2, 5):
  - `type Report struct { Org, Email, ReportID, Domain string; RangeBegin, RangeEnd time.Time; Records []Record }`
  - `type Record struct { SourceIP string; Count int; Disposition, DKIM, SPF, HeaderFrom string }`
  - `func Parse(r io.Reader) (*Report, error)`

- [ ] **Step 1: Write the failing tests**

```go
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
		"not xml":       "this is not xml at all {",
		"wrong root":    `<not_feedback><report_metadata/></not_feedback>`,
		"no org":        `<feedback><report_metadata><report_id>r</report_id></report_metadata><policy_published><domain>d</domain></policy_published><record><row><source_ip>1.2.3.4</source_ip><count>1</count></row></record></feedback>`,
		"no report id":  `<feedback><report_metadata><org_name>o</org_name></report_metadata><policy_published><domain>d</domain></policy_published><record><row><source_ip>1.2.3.4</source_ip><count>1</count></row></record></feedback>`,
		"no domain":     `<feedback><report_metadata><org_name>o</org_name><report_id>r</report_id></report_metadata><record><row><source_ip>1.2.3.4</source_ip><count>1</count></row></record></feedback>`,
		"zero records":  `<feedback><report_metadata><org_name>o</org_name><report_id>r</report_id></report_metadata><policy_published><domain>d</domain></policy_published></feedback>`,
	}
	for name, xml := range cases {
		if _, err := Parse(strings.NewReader(xml)); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/dmarcreport/ -v`
Expected: FAIL to build — `Parse`, `Report` undefined.

- [ ] **Step 3: Write the implementation**

```go
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
	SourceIP                          string
	Count                             int
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
	if f.ReportMetadata.OrgName == "" || f.ReportMetadata.ReportID == "" {
		return nil, fmt.Errorf("dmarc xml: missing org_name or report_id")
	}
	if f.PolicyPublished.Domain == "" {
		return nil, fmt.Errorf("dmarc xml: missing policy_published domain")
	}
	if len(f.Records) == 0 {
		return nil, fmt.Errorf("dmarc xml: no records")
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
```

Note the wrong-root test: `xml.Decoder.Decode` into a struct with `XMLName xml.Name \`xml:"feedback"\`` returns an error for a different root element — that's what makes the "wrong root" case fail parse.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dmarcreport/ -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Vet and commit**

Run: `go vet ./...`

```bash
git add internal/dmarcreport/
git commit -m "feat(dmarcreport): RFC 7489 aggregate report parser"
```

---

### Task 2: `internal/dmarcreport` — attachment extraction from the report email

**Files:**
- Create: `internal/dmarcreport/extract.go`
- Test: `internal/dmarcreport/extract_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces (used by Task 5):
  - `func FromEmail(r io.Reader) ([]byte, error)` — reads a full RFC 822 message, finds the first gzip/zip/xml report part, and returns the decompressed XML bytes (capped at `MaxXMLBytes`). Error when no report payload is found or a cap is exceeded.
  - `const MaxXMLBytes = 50 << 20`

Real-world shapes this must handle (each gets a test):
- Google: single-part message, `Content-Type: application/zip`, `Content-Transfer-Encoding: base64` — the whole body is the attachment, no multipart.
- Yahoo/Microsoft style: `multipart/mixed` with an `application/gzip` (or `application/x-gzip`) part, base64 CTE, filename `...xml.gz`.
- Bare XML part (`application/xml` or `text/xml`), 7bit/8bit CTE.
- `application/octet-stream` with a `.zip`/`.gz`/`.xml` filename — sniff by extension, then by magic bytes (`PK\x03\x04` for zip, `\x1f\x8b` for gzip) when there's no useful name.
- `multipart/mixed` nested inside `multipart/alternative`+text parts — recursion required.

- [ ] **Step 1: Write the failing tests**

The tests build real MIME messages in-memory (no binary fixtures): gzip via `compress/gzip.Writer`, zip via `archive/zip.Writer`, base64 via `encoding/base64`, multipart via `mime/multipart.Writer`. Include at minimum:

```go
package dmarcreport

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"strings"
	"testing"
)

const tinyXML = `<feedback><report_metadata><org_name>o</org_name><report_id>r1</report_id><date_range><begin>1</begin><end>2</end></date_range></report_metadata><policy_published><domain>d.example</domain></policy_published><record><row><source_ip>192.0.2.1</source_ip><count>1</count><policy_evaluated><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row></record></feedback>`

func gzipBytes(t *testing.T, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.Write([]byte(data))
	gw.Close()
	return buf.Bytes()
}

func zipBytes(t *testing.T, name, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create(name)
	f.Write([]byte(data))
	zw.Close()
	return buf.Bytes()
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// singlePartZip is the Google shape: whole body is one base64 zip.
func singlePartZip(t *testing.T) string {
	return "From: noreply-dmarc-support@google.com\r\n" +
		"To: dmarc@sys.example\r\n" +
		"Subject: Report Domain: client.example\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: application/zip; name=\"google.com!client.example!1!2.zip\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"\r\n" + b64(zipBytes(t, "google.com!client.example!1!2.xml", tinyXML)) + "\r\n"
}

// multipartGzip is the Yahoo shape: multipart/mixed with a gzip part.
func multipartGzip(t *testing.T) string {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", "text/plain; charset=us-ascii")
	p, _ := mw.CreatePart(h)
	p.Write([]byte("This is an aggregate report."))
	h = textproto.MIMEHeader{}
	h.Set("Content-Type", "application/gzip")
	h.Set("Content-Disposition", `attachment; filename="yahoo!client.example!1!2.xml.gz"`)
	h.Set("Content-Transfer-Encoding", "base64")
	p, _ = mw.CreatePart(h)
	p.Write([]byte(b64(gzipBytes(t, tinyXML))))
	mw.Close()
	return "From: dmarchelp@yahooinc.com\r\nTo: dmarc@sys.example\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=" + mw.Boundary() + "\r\n\r\n" + body.String()
}

func TestFromEmailShapes(t *testing.T) {
	cases := map[string]string{
		"google single-part zip": singlePartZip(t),
		"yahoo multipart gzip":   multipartGzip(t),
	}
	for name, msg := range cases {
		got, err := FromEmail(strings.NewReader(msg))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if string(got) != tinyXML {
			t.Errorf("%s: extracted %d bytes, not the expected XML", name, len(got))
		}
	}
}

func TestFromEmailBareXMLPart(t *testing.T) {
	msg := "From: a@b\r\nMIME-Version: 1.0\r\nContent-Type: application/xml\r\n\r\n" + tinyXML
	got, err := FromEmail(strings.NewReader(msg))
	if err != nil || string(got) != tinyXML {
		t.Fatalf("bare xml: err=%v len=%d", err, len(got))
	}
}

func TestFromEmailOctetStreamByExtensionAndMagic(t *testing.T) {
	// octet-stream + .gz filename
	withName := "From: a@b\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: application/octet-stream; name=\"r.xml.gz\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + b64(gzipBytes(t, tinyXML))
	if got, err := FromEmail(strings.NewReader(withName)); err != nil || string(got) != tinyXML {
		t.Errorf("by extension: err=%v", err)
	}
	// octet-stream, no filename: gzip magic bytes decide
	noName := "From: a@b\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + b64(gzipBytes(t, tinyXML))
	if got, err := FromEmail(strings.NewReader(noName)); err != nil || string(got) != tinyXML {
		t.Errorf("by magic: err=%v", err)
	}
}

func TestFromEmailNoReportFound(t *testing.T) {
	msg := "From: a@b\r\nContent-Type: text/plain\r\n\r\njust text"
	if _, err := FromEmail(strings.NewReader(msg)); err == nil {
		t.Fatal("expected error for text-only message")
	}
}

func TestFromEmailDecompressionCap(t *testing.T) {
	// A ~200MB-of-zeros gzip is a few hundred KB compressed; extraction must
	// stop at MaxXMLBytes instead of inflating it all.
	huge := strings.Repeat("\x00", 200<<20>>8) // build 200MB via repeated writes instead if memory-shy; see note
	_ = huge
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte{0}, 1<<20)
	for i := 0; i < 200; i++ {
		gw.Write(chunk)
	}
	gw.Close()
	msg := "From: a@b\r\nMIME-Version: 1.0\r\nContent-Type: application/gzip\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + b64(buf.Bytes())
	if _, err := FromEmail(strings.NewReader(msg)); err == nil {
		t.Fatal("expected decompression-cap error")
	}
	_ = fmt.Sprint() // keep fmt import if otherwise unused
}
```

(Clean up the cap test when implementing — the `huge`/`fmt` scaffolding lines above are noise; write it with just the chunked gzip writer.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/dmarcreport/ -run FromEmail -v`
Expected: FAIL to build — `FromEmail` undefined.

- [ ] **Step 3: Write the implementation**

Create `internal/dmarcreport/extract.go`:

```go
package dmarcreport

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
)

// MaxXMLBytes caps the decompressed report size. Aggregate reports are
// typically well under 1 MB; the cap exists so a hostile gzip/zip bomb
// cannot balloon a 15 MB message into gigabytes of memory.
const MaxXMLBytes = 50 << 20

// FromEmail reads a full RFC 822 report email and returns the decompressed
// aggregate-report XML from its first gzip/zip/xml payload. Reporters differ
// in shape (Google sends a single-part base64 zip body; Yahoo a
// multipart/mixed gzip part), so detection tries, in order: filename
// extension, declared media type, magic bytes.
func FromEmail(r io.Reader) ([]byte, error) {
	msg, err := mail.ReadMessage(r)
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}
	h := textproto.MIMEHeader(msg.Header)
	return fromPart(h, msg.Body)
}

// fromPart handles one MIME entity: recurses into multiparts, otherwise
// decodes the transfer encoding and tries to extract a report payload.
func fromPart(h textproto.MIMEHeader, body io.Reader) ([]byte, error) {
	mediaType, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		mediaType = "text/plain"
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("multipart: %w", err)
			}
			if xmlBytes, err := fromPart(p.Header, p); err == nil {
				return xmlBytes, nil
			}
		}
		return nil, fmt.Errorf("no report payload in multipart message")
	}

	decoded := decodeCTE(h.Get("Content-Transfer-Encoding"), body)
	// Cap the raw payload read: the SMTP server already caps the whole
	// message, but fromPart must stand alone (tests, future callers).
	raw, err := io.ReadAll(io.LimitReader(decoded, MaxXMLBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read part: %w", err)
	}
	if len(raw) > MaxXMLBytes {
		return nil, fmt.Errorf("part exceeds %d bytes", MaxXMLBytes)
	}
	return extractPayload(mediaType, partFilename(h, params), raw)
}

// decodeCTE undoes the Content-Transfer-Encoding. multipart.Part decodes
// quoted-printable itself, but base64 — which every real report attachment
// uses — is left to us, as is the top-level (non-multipart) body.
func decodeCTE(cte string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, newLineStrippingReader(r))
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	default: // 7bit, 8bit, binary, empty
		return r
	}
}

// newLineStrippingReader removes CR/LF so wrapped base64 bodies decode.
func newLineStrippingReader(r io.Reader) io.Reader {
	return &lineStripper{r: r}
}

type lineStripper struct{ r io.Reader }

func (l *lineStripper) Read(p []byte) (int, error) {
	buf := make([]byte, len(p))
	for {
		n, err := l.r.Read(buf)
		j := 0
		for _, b := range buf[:n] {
			if b != '\r' && b != '\n' {
				p[j] = b
				j++
			}
		}
		if j > 0 || err != nil {
			return j, err
		}
	}
}

func partFilename(h textproto.MIMEHeader, ctParams map[string]string) string {
	if _, params, err := mime.ParseMediaType(h.Get("Content-Disposition")); err == nil {
		if fn := params["filename"]; fn != "" {
			return fn
		}
	}
	return ctParams["name"]
}

// extractPayload turns one decoded part into report XML, or reports that
// this part isn't a report payload (so multipart walking can move on).
func extractPayload(mediaType, filename string, raw []byte) ([]byte, error) {
	lower := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(lower, ".zip") || mediaType == "application/zip" || bytes.HasPrefix(raw, []byte("PK\x03\x04")):
		return unzipReport(raw)
	case strings.HasSuffix(lower, ".gz") || mediaType == "application/gzip" || mediaType == "application/x-gzip" || bytes.HasPrefix(raw, []byte{0x1f, 0x8b}):
		return gunzipReport(raw)
	case strings.HasSuffix(lower, ".xml") || mediaType == "application/xml" || mediaType == "text/xml":
		return raw, nil
	}
	return nil, fmt.Errorf("part %q (%s) is not a report payload", filename, mediaType)
}

func gunzipReport(raw []byte) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	defer gz.Close()
	out, err := io.ReadAll(io.LimitReader(gz, MaxXMLBytes+1))
	if err != nil {
		return nil, fmt.Errorf("gunzip: %w", err)
	}
	if len(out) > MaxXMLBytes {
		return nil, fmt.Errorf("decompressed report exceeds %d bytes", MaxXMLBytes)
	}
	return out, nil
}

func unzipReport(raw []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return nil, fmt.Errorf("unzip: %w", err)
	}
	for _, f := range zr.File {
		if !strings.HasSuffix(strings.ToLower(f.Name), ".xml") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("unzip %s: %w", f.Name, err)
		}
		defer rc.Close()
		out, err := io.ReadAll(io.LimitReader(rc, MaxXMLBytes+1))
		if err != nil {
			return nil, fmt.Errorf("unzip %s: %w", f.Name, err)
		}
		if len(out) > MaxXMLBytes {
			return nil, fmt.Errorf("decompressed report exceeds %d bytes", MaxXMLBytes)
		}
		return out, nil
	}
	return nil, fmt.Errorf("zip contains no .xml entry")
}
```

Note: `textproto.MIMEHeader(msg.Header)` — `mail.Header` is `map[string][]string` with canonicalized keys, so the conversion is direct.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/dmarcreport/ -v`
Expected: PASS (all Task 1 + Task 2 tests).

- [ ] **Step 5: Vet and commit**

Run: `go vet ./...`

```bash
git add internal/dmarcreport/
git commit -m "feat(dmarcreport): extract report XML from gzip/zip/xml email payloads"
```

---

### Task 3: store — DMARC tables, insert with dedup, retention prune

**Files:**
- Modify: `internal/store/store.go` (append two tables to the `schema` constant)
- Create: `internal/store/dmarc.go`
- Test: `internal/store/dmarc_test.go`

**Interfaces:**
- Consumes: store conventions (`Now`, RFC3339 strings, MaxOpenConns(1) tx rule).
- Produces (used by Tasks 5, 6, 7, 9):
  - `type DMARCReport struct { ID int64; Org, ReportID, Domain, RangeBegin, RangeEnd, ReceivedAt, Raw string }`
  - `type DMARCRecord struct { ID, ReportID int64; SourceIP string; Count int64; Disposition, DKIM, SPF, HeaderFrom string }`
  - `func (s *Store) InsertDMARCReport(rep *DMARCReport, recs []DMARCRecord) (id int64, duplicate bool, err error)` — one transaction; `duplicate=true` (no error) on the `UNIQUE(org, report_id)` constraint.
  - `func (s *Store) PruneDMARCReports(before string) (int64, error)` — deletes reports with `received_at < before` and their records; returns reports deleted.
  - `func (s *Store) CountDMARCReports() (int64, error)` — `SELECT COUNT(*) FROM dmarc_reports`; Task 5's receiver tests assert through it (the richer list queries only arrive in Task 6).

- [ ] **Step 1: Add the tables to the schema constant**

Append inside the `schema` constant in `internal/store/store.go` (after the `blocklist_events` table):

```sql
CREATE TABLE IF NOT EXISTS dmarc_reports (
  id INTEGER PRIMARY KEY,
  org TEXT NOT NULL,
  report_id TEXT NOT NULL,
  domain TEXT NOT NULL,
  range_begin TEXT NOT NULL,
  range_end TEXT NOT NULL,
  received_at TEXT NOT NULL,
  raw TEXT NOT NULL DEFAULT '',
  UNIQUE(org, report_id)
);
CREATE TABLE IF NOT EXISTS dmarc_records (
  id INTEGER PRIMARY KEY,
  report_id INTEGER NOT NULL REFERENCES dmarc_reports(id) ON DELETE CASCADE,
  source_ip TEXT NOT NULL,
  count INTEGER NOT NULL,
  disposition TEXT NOT NULL DEFAULT '',
  dkim TEXT NOT NULL DEFAULT '',
  spf TEXT NOT NULL DEFAULT '',
  header_from TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_dmarc_reports_received ON dmarc_reports(received_at);
CREATE INDEX IF NOT EXISTS idx_dmarc_records_report ON dmarc_records(report_id);
```

The store opens with `_pragma=foreign_keys(1)`, so `ON DELETE CASCADE` is enforced — `PruneDMARCReports` only needs to delete from `dmarc_reports`.

- [ ] **Step 2: Write the failing tests**

```go
package store

import (
	"path/filepath"
	"testing"
)

func dmStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleReport(reportID string) (*DMARCReport, []DMARCRecord) {
	rep := &DMARCReport{
		Org: "google.com", ReportID: reportID, Domain: "client.example",
		RangeBegin: "2026-08-01T00:00:00Z", RangeEnd: "2026-08-02T00:00:00Z",
		ReceivedAt: "2026-08-02T06:00:00Z", Raw: "<feedback/>",
	}
	recs := []DMARCRecord{
		{SourceIP: "203.0.113.7", Count: 11, Disposition: "none", DKIM: "pass", SPF: "pass", HeaderFrom: "client.example"},
		{SourceIP: "198.51.100.9", Count: 3, Disposition: "quarantine", DKIM: "fail", SPF: "fail", HeaderFrom: "client.example"},
	}
	return rep, recs
}

func TestInsertDMARCReportAndDedup(t *testing.T) {
	s := dmStore(t)
	rep, recs := sampleReport("r-1")
	id, dup, err := s.InsertDMARCReport(rep, recs)
	if err != nil || dup || id == 0 {
		t.Fatalf("insert: id=%d dup=%v err=%v", id, dup, err)
	}
	// Same (org, report_id) again: duplicate, no error, no second row.
	rep2, recs2 := sampleReport("r-1")
	_, dup, err = s.InsertDMARCReport(rep2, recs2)
	if err != nil || !dup {
		t.Fatalf("re-insert: dup=%v err=%v, want true nil", dup, err)
	}
	// Different report_id: fresh insert.
	rep3, recs3 := sampleReport("r-2")
	if _, dup, err = s.InsertDMARCReport(rep3, recs3); err != nil || dup {
		t.Fatalf("second report: dup=%v err=%v", dup, err)
	}
}

func TestPruneDMARCReports(t *testing.T) {
	s := dmStore(t)
	old, oldRecs := sampleReport("r-old")
	old.ReceivedAt = "2026-05-01T00:00:00Z"
	s.InsertDMARCReport(old, oldRecs)
	fresh, freshRecs := sampleReport("r-new")
	s.InsertDMARCReport(fresh, freshRecs)

	n, err := s.PruneDMARCReports("2026-06-01T00:00:00Z")
	if err != nil || n != 1 {
		t.Fatalf("prune: n=%d err=%v, want 1 nil", n, err)
	}
	// Cascade removed the old report's records; the fresh report's remain.
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM dmarc_records`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("records after prune: %d, want 2", count)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/store/ -run DMARC -v`
Expected: FAIL to build — `InsertDMARCReport` undefined.

- [ ] **Step 4: Write the implementation**

Create `internal/store/dmarc.go`:

```go
package store

import "strings"

// DMARCReport is one stored aggregate report. Raw keeps the decompressed
// XML for debugging parser gaps; retention (PruneDMARCReports) bounds it.
type DMARCReport struct {
	ID                                            int64
	Org, ReportID, Domain                         string
	RangeBegin, RangeEnd, ReceivedAt, Raw         string
}

// DMARCRecord is one per-source row of a report.
type DMARCRecord struct {
	ID, ReportID                        int64
	SourceIP                            string
	Count                               int64
	Disposition, DKIM, SPF, HeaderFrom  string
}

// InsertDMARCReport stores a report and its records in one transaction.
// Reporters re-send reports, so (org, report_id) is UNIQUE: a constraint hit
// returns duplicate=true with no error — the caller accepts the message and
// drops it (re-rejecting would just make the reporter retry forever).
func (s *Store) InsertDMARCReport(rep *DMARCReport, recs []DMARCRecord) (int64, bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()

	// MaxOpenConns(1): every statement here must use tx, never s.db.
	res, err := tx.Exec(`INSERT INTO dmarc_reports
		(org, report_id, domain, range_begin, range_end, received_at, raw)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		rep.Org, rep.ReportID, rep.Domain, rep.RangeBegin, rep.RangeEnd, rep.ReceivedAt, rep.Raw)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, true, nil
		}
		return 0, false, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, false, err
	}
	for _, r := range recs {
		if _, err := tx.Exec(`INSERT INTO dmarc_records
			(report_id, source_ip, count, disposition, dkim, spf, header_from)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			id, r.SourceIP, r.Count, r.Disposition, r.DKIM, r.SPF, r.HeaderFrom); err != nil {
			return 0, false, err
		}
	}
	return id, false, tx.Commit()
}

// PruneDMARCReports deletes reports received before the given RFC3339 time.
// dmarc_records rows go with them via ON DELETE CASCADE (foreign_keys is on).
func (s *Store) PruneDMARCReports(before string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM dmarc_reports WHERE received_at < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) CountDMARCReports() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM dmarc_reports`).Scan(&n)
	return n, err
}
```

Add one assertion using `CountDMARCReports` to `TestInsertDMARCReportAndDedup` (count must be 2 at the end — the dedup'd re-insert must not have bumped it).

The UNIQUE-detection-by-substring matches the existing `migrate()` precedent for matching driver error text; check whether the api package's `enqueueOrReplay` already has a constraint-error helper (`grep -rn "UNIQUE constraint" internal/`) and reuse its approach if one exists.

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/store/ -run DMARC -v` then the full package `go test ./internal/store/`
Expected: PASS; existing tests unaffected.

- [ ] **Step 6: Vet and commit**

Run: `go vet ./...`

```bash
git add internal/store/store.go internal/store/dmarc.go internal/store/dmarc_test.go
git commit -m "feat(store): dmarc report tables with dedup insert and retention prune"
```

---

### Task 4: notify — own-mail-failing-DMARC alert with 24h cooldown

**Files:**
- Modify: `internal/notify/notifier.go` (add method after `BlocklistCleared`)
- Test: `internal/notify/notifier_test.go` (append)

**Interfaces:**
- Consumes: `enqueue` helper, `Store.GetState`/`SetState` (`notify_state`), `store.FmtTime`/`store.ParseTime`, test helpers `fixture`/`systemEmails`.
- Produces (used by Task 5):
  - `func (n *Notifier) DMARCFailure(domain string, count int)` — enqueues at most one alert per domain per 24h; cooldown key `"dmarc_alert_" + domain` in `notify_state` holding the last-sent RFC3339 time.

- [ ] **Step 1: Write the failing test**

```go
func TestDMARCFailureCooldown(t *testing.T) {
	s, n, _ := fixture(t, true)

	n.DMARCFailure("client.example", 14)
	emails := systemEmails(t, s)
	if len(emails) != 1 {
		t.Fatalf("first alert: %d system emails, want 1", len(emails))
	}
	if !strings.Contains(emails[0].Subject, "client.example") ||
		!strings.Contains(emails[0].BodyText, "14") {
		t.Errorf("alert lacks domain/count: subject=%q body=%q", emails[0].Subject, emails[0].BodyText)
	}

	// Within the cooldown: silent.
	n.DMARCFailure("client.example", 5)
	if got := len(systemEmails(t, s)); got != 1 {
		t.Fatalf("cooldown violated: %d emails, want 1", got)
	}

	// A different domain has its own cooldown.
	n.DMARCFailure("other.example", 2)
	if got := len(systemEmails(t, s)); got != 2 {
		t.Fatalf("per-domain cooldown: %d emails, want 2", got)
	}

	// Cooldown expired: fires again.
	s.SetState("dmarc_alert_client.example", store.FmtTime(time.Now().UTC().Add(-25*time.Hour)))
	n.DMARCFailure("client.example", 7)
	if got := len(systemEmails(t, s)); got != 3 {
		t.Fatalf("after expiry: %d emails, want 3", got)
	}
}

func TestDMARCFailureFailOpenUnverified(t *testing.T) {
	s, n, _ := fixture(t, false)
	n.DMARCFailure("client.example", 3)
	if got := len(systemEmails(t, s)); got != 0 {
		t.Fatalf("unverified system domain must skip silently, got %d", got)
	}
	// A skipped send must NOT start the cooldown — otherwise verifying the
	// system domain within 24h of a failure silently swallows the alert.
	if v, _ := s.GetState("dmarc_alert_client.example"); v != "" {
		t.Fatalf("cooldown set despite skipped send: %q", v)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/notify/ -run DMARC -v`
Expected: FAIL to build — `DMARCFailure` undefined.

- [ ] **Step 3: Write the implementation**

Add after `BlocklistCleared` in `internal/notify/notifier.go`:

```go
// DMARCFailure is called by the inbound report handler when a stored report
// shows our own egress IP failing DMARC for a domain — the "our signing or
// DNS broke" early-warning. Reports arrive in bursts (one per reporter per
// day), so a 24h per-domain cooldown in notify_state keeps that to one email
// per domain per day. The cooldown is only recorded when the alert was
// actually enqueued: a fail-open skip (system domain unverified) must not
// swallow the next attempt.
func (n *Notifier) DMARCFailure(domain string, count int) {
	key := "dmarc_alert_" + domain
	if last, _ := n.Store.GetState(key); last != "" {
		if time.Now().UTC().Sub(store.ParseTime(last)) < 24*time.Hour {
			return
		}
	}
	sent, err := n.enqueue("doevoe: our mail is failing DMARC for "+domain,
		fmt.Sprintf("A DMARC aggregate report shows %d message(s) from our own sending IP failing both DKIM and SPF evaluation for %s.\nThis usually means a DNS or signing problem on our side — check the domain's records.\n\n%s/admin/dmarc\n", count, domain, n.BaseURL))
	if err != nil {
		slog.Error("notifier: dmarc failure alert failed", "domain", domain, "err", err)
		return
	}
	if sent {
		if err := n.Store.SetState(key, store.FmtTime(time.Now().UTC())); err != nil {
			slog.Error("notifier: setting dmarc cooldown failed", "domain", domain, "err", err)
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/notify/ -v`
Expected: PASS including all pre-existing tests.

- [ ] **Step 5: Vet and commit**

Run: `go vet ./...`

```bash
git add internal/notify/notifier.go internal/notify/notifier_test.go
git commit -m "feat(notify): own-mail DMARC failure alert with 24h per-domain cooldown"
```

---

### Task 5: `internal/inbound` — the SMTP receiver

**Files:**
- Create: `internal/inbound/inbound.go`
- Test: `internal/inbound/inbound_test.go`
- Create: `internal/inbound/README.md` is NOT needed (that convention is for Craft CMS projects, not this repo)

**Interfaces:**
- Consumes: `dmarcreport.FromEmail` / `dmarcreport.Parse` (Tasks 1–2), `store.InsertDMARCReport` (Task 3), the `OnOwnFailure` callback (Task 4's `notifier.DMARCFailure` is wired in Task 9), `go-smtp` server API: `smtp.NewServer(be Backend)`, `Backend.NewSession(*smtp.Conn) (smtp.Session, error)`, `Session{Reset(); Logout() error; Mail(from string, opts *smtp.MailOptions) error; Rcpt(to string, opts *smtp.RcptOptions) error; Data(r io.Reader) error}`, `Server.Addr/Domain/MaxMessageBytes/ReadTimeout/WriteTimeout`, `Server.ListenAndServe()/Serve(net.Listener)/Shutdown(ctx)/Close()`, `&smtp.SMTPError{Code, EnhancedCode, Message}`.
- Produces (used by Task 9):
  - `type Server struct { Store *store.Store; ReportAddr string; EgressIP string; Hostname string; OnOwnFailure func(domain string, count int) }`
  - `func (s *Server) Serve(ctx context.Context, l net.Listener) error` — serves SMTP on an existing listener until ctx cancels, then shuts down gracefully. The caller owns the `net.Listen` (main.go binds synchronously at startup so a bind failure is a hard config-style exit, per the spec's error table; tests bind `127.0.0.1:0`). No `Run(addr)` convenience wrapper — nothing would use it.

- [ ] **Step 1: Write the failing test**

End-to-end over a real socket: start `Serve` on `127.0.0.1:0`, deliver messages with go-smtp's client, assert against a real temp store.

```go
package inbound

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"

	"doevoe/internal/store"
)

// deliver connects to addr and submits one message; returns the error from
// the first failing SMTP step so tests can assert on rejections.
func deliver(t *testing.T, addr, rcpt, msg string) error {
	t.Helper()
	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Mail("reporter@google.com", nil); err != nil {
		return err
	}
	if err := c.Rcpt(rcpt, nil); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	return w.Close()
}

func startServer(t *testing.T) (*store.Store, string, *[]struct {
	Domain string
	Count  int
}) {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	var alerts []struct {
		Domain string
		Count  int
	}
	srv := &Server{
		Store: s, ReportAddr: "dmarc@sys.example", EgressIP: "203.0.113.7",
		Hostname: "mail.sys.example",
		OnOwnFailure: func(domain string, count int) {
			alerts = append(alerts, struct {
				Domain string
				Count  int
			}{domain, count})
		},
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { srv.Serve(ctx, l); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	})
	return s, l.Addr().String(), &alerts
}

// reportMsg builds a single-part bare-XML report message (the simplest valid
// shape — extraction of gzip/zip is covered by dmarcreport's own tests).
func reportMsg(reportID, sourceIP, dkim, spf string, count int) string {
	xml := `<feedback><report_metadata><org_name>google.com</org_name><report_id>` + reportID + `</report_id><date_range><begin>1753999200</begin><end>1754085600</end></date_range></report_metadata><policy_published><domain>client.example</domain></policy_published><record><row><source_ip>` + sourceIP + `</source_ip><count>` + strconv.Itoa(count) + `</count><policy_evaluated><disposition>none</disposition><dkim>` + dkim + `</dkim><spf>` + spf + `</spf></policy_evaluated></row><identifiers><header_from>client.example</header_from></identifiers></record></feedback>`
	return "From: reporter@google.com\r\nTo: dmarc@sys.example\r\nSubject: report\r\nMIME-Version: 1.0\r\nContent-Type: application/xml\r\n\r\n" + xml
}

// Data() stores synchronously before replying 250, so a returned deliver()
// means the report is already in (or knowingly dropped from) the store — no
// polling needed.
func mustCount(t *testing.T, s *store.Store, want int64) {
	t.Helper()
	n, err := s.CountDMARCReports()
	if err != nil {
		t.Fatal(err)
	}
	if n != want {
		t.Fatalf("stored reports: %d, want %d", n, want)
	}
}

func TestReceiveStoresReport(t *testing.T) {
	s, addr, _ := startServer(t)
	if err := deliver(t, addr, "dmarc@sys.example", reportMsg("rid-1", "198.51.100.9", "fail", "fail", 3)); err != nil {
		t.Fatal(err)
	}
	mustCount(t, s, 1)
}

func TestRcptRejectsNonReportAddress(t *testing.T) {
	_, addr, _ := startServer(t)
	err := deliver(t, addr, "someone@else.example", reportMsg("rid-2", "1.2.3.4", "pass", "pass", 1))
	if err == nil || !strings.Contains(err.Error(), "550") {
		t.Fatalf("want 550 rejection, got %v", err)
	}
}

func TestMalformedAcceptedAndDropped(t *testing.T) {
	s, addr, _ := startServer(t)
	msg := "From: a@b\r\nContent-Type: text/plain\r\n\r\nnot a report"
	if err := deliver(t, addr, "dmarc@sys.example", msg); err != nil {
		t.Fatalf("malformed report must be accepted at SMTP level, got %v", err)
	}
	mustCount(t, s, 0)
}

func TestDuplicateAccepted(t *testing.T) {
	s, addr, _ := startServer(t)
	msg := reportMsg("rid-dup", "1.2.3.4", "pass", "pass", 1)
	if err := deliver(t, addr, "dmarc@sys.example", msg); err != nil {
		t.Fatal(err)
	}
	if err := deliver(t, addr, "dmarc@sys.example", msg); err != nil {
		t.Fatalf("duplicate must be accepted (250), got %v", err)
	}
	mustCount(t, s, 1)
}

func TestOwnFailureTriggersCallback(t *testing.T) {
	_, addr, alerts := startServer(t)
	// Source IP == EgressIP, both dkim and spf fail → callback.
	if err := deliver(t, addr, "dmarc@sys.example", reportMsg("rid-own", "203.0.113.7", "fail", "fail", 14)); err != nil {
		t.Fatal(err)
	}
	if len(*alerts) != 1 || (*alerts)[0].Domain != "client.example" || (*alerts)[0].Count != 14 {
		t.Fatalf("alerts: %+v", *alerts)
	}
}

func TestOtherIPFailureNoCallback(t *testing.T) {
	s, addr, alerts := startServer(t)
	if err := deliver(t, addr, "dmarc@sys.example", reportMsg("rid-spoof", "198.51.100.9", "fail", "fail", 9)); err != nil {
		t.Fatal(err)
	}
	mustCount(t, s, 1)
	if len(*alerts) != 0 {
		t.Fatalf("spoofing by other IPs must not alert: %+v", *alerts)
	}
}
```

Imports for the test file: add `strconv`; the `time` import is only needed by `startServer`'s shutdown wait.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/inbound/ -v`
Expected: FAIL to build — `Server` undefined.

- [ ] **Step 3: Write the implementation**

```go
// Package inbound is doevoe's SMTP receiver for DMARC aggregate reports.
// It is deliberately not a mail server: it accepts mail for exactly one
// address (dmarc@<system-domain>), never relays, and needs no auth. Every
// accepted message is parsed and stored synchronously in Data(), so a 250
// reply means the report is durably in SQLite (or was a knowingly-dropped
// malformed/duplicate one).
package inbound

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-smtp"

	"doevoe/internal/dmarcreport"
	"doevoe/internal/store"
)

const (
	maxMessageBytes = 15 << 20
	ioTimeout       = 2 * time.Minute
)

type Server struct {
	Store      *store.Store
	ReportAddr string // the only RCPT we accept, e.g. "dmarc@sys.example"
	EgressIP   string // our own sending IP, for the own-failure alert
	Hostname   string // EHLO banner domain
	// OnOwnFailure fires when a stored report shows EgressIP failing both
	// DKIM and SPF — wired to notify.DMARCFailure (which owns the cooldown).
	OnOwnFailure func(domain string, count int)
}

// Serve serves SMTP on l until ctx is cancelled, then shuts down gracefully.
// The caller owns the listener: main.go binds at startup (so a bind failure
// exits like any other misconfiguration), tests bind 127.0.0.1:0.
func (s *Server) Serve(ctx context.Context, l net.Listener) error {
	srv := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		return &session{srv: s}, nil
	}))
	srv.Domain = s.Hostname
	srv.MaxMessageBytes = maxMessageBytes
	srv.ReadTimeout = ioTimeout
	srv.WriteTimeout = ioTimeout

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(l) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
		srv.Close()
		<-errCh
		return nil
	case err := <-errCh:
		return err
	}
}

type session struct {
	srv *Server
}

func (se *session) Reset()        {}
func (se *session) Logout() error { return nil }

func (se *session) Mail(from string, opts *smtp.MailOptions) error { return nil }

func (se *session) Rcpt(to string, opts *smtp.RcptOptions) error {
	// The one gate that keeps this from being an open relay or a general
	// mailbox: only the report address exists, everything else is 550.
	if !strings.EqualFold(strings.TrimSpace(to), se.srv.ReportAddr) {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "no such user"}
	}
	return nil
}

func (se *session) Data(r io.Reader) error {
	// One bad message must not kill the connection handler.
	defer func() {
		if p := recover(); p != nil {
			slog.Error("inbound: panic handling report", "panic", p)
		}
	}()
	xmlBytes, err := dmarcreport.FromEmail(r)
	if err != nil {
		// Malformed (no payload / bomb / broken MIME): accept and drop.
		// A 5xx would only make the reporter retry a message that will
		// never parse; the raw isn't stored because there's nothing to key
		// it under.
		slog.Warn("inbound: dropping unparsable report message", "err", err)
		return nil
	}
	rep, err := dmarcreport.Parse(strings.NewReader(string(xmlBytes)))
	if err != nil {
		slog.Warn("inbound: dropping malformed report xml", "err", err)
		return nil
	}
	storeRep := &store.DMARCReport{
		Org: rep.Org, ReportID: rep.ReportID, Domain: rep.Domain,
		RangeBegin: store.FmtTime(rep.RangeBegin), RangeEnd: store.FmtTime(rep.RangeEnd),
		ReceivedAt: store.Now(), Raw: string(xmlBytes),
	}
	var recs []store.DMARCRecord
	ownFailures := 0
	for _, r := range rep.Records {
		recs = append(recs, store.DMARCRecord{
			SourceIP: r.SourceIP, Count: int64(r.Count), Disposition: r.Disposition,
			DKIM: r.DKIM, SPF: r.SPF, HeaderFrom: r.HeaderFrom,
		})
		// Both evaluations failing from our own IP is the "our signing or
		// DNS broke" signal; spoofing from other IPs stays page-only.
		if r.SourceIP == se.srv.EgressIP && r.DKIM == "fail" && r.SPF == "fail" {
			ownFailures += r.Count
		}
	}
	_, duplicate, err := se.srv.Store.InsertDMARCReport(storeRep, recs)
	if err != nil {
		// A store error is transient (disk, lock): 451 so the reporter
		// retries later instead of losing the report.
		slog.Error("inbound: storing report failed", "org", rep.Org, "report_id", rep.ReportID, "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 3, 0}, Message: "temporary storage failure"}
	}
	if duplicate {
		slog.Info("inbound: duplicate report dropped", "org", rep.Org, "report_id", rep.ReportID)
		return nil
	}
	slog.Info("inbound: stored dmarc report", "org", rep.Org, "domain", rep.Domain, "records", len(recs))
	if ownFailures > 0 && se.srv.OnOwnFailure != nil {
		se.srv.OnOwnFailure(rep.Domain, ownFailures)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/inbound/ -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Vet, full suite, commit**

Run: `go vet ./... && go test ./...`

```bash
git add internal/inbound/
git commit -m "feat(inbound): SMTP receiver for DMARC aggregate reports"
```

---

### Task 6: store — DMARC queries for the admin page

**Files:**
- Modify: `internal/store/dmarc.go` (append)
- Test: `internal/store/dmarc_test.go` (append)

**Interfaces:**
- Consumes: Task 3's tables and test helpers.
- Produces (used by Task 7):
  - `type DMARCDomainSummary struct { Domain string; Pass, Fail int64 }` — message counts (SUM of record counts); a record passes when `dkim='pass' OR spf='pass'` (DMARC needs one aligned pass), fails otherwise.
  - `func (s *Store) DMARCSummary(from, to string) ([]DMARCDomainSummary, error)` — grouped by domain, windowed on `dmarc_reports.received_at` (`from` inclusive, `to` exclusive; empty string = unbounded side), ordered by domain.
  - `type DMARCSource struct { SourceIP string; Count int64 }`
  - `func (s *Store) DMARCTopFailingSources(from, to string, limit int) ([]DMARCSource, error)` — failing messages only, ordered by count desc.
  - `func (s *Store) ListDMARCReports(from, to string, limit int) ([]DMARCReportListItem, error)` where `type DMARCReportListItem struct { DMARCReport; RecordCount int64 }` — newest received first, `Raw` NOT selected (list pages don't need megabytes of XML).

- [ ] **Step 1: Write the failing tests**

Seed via `InsertDMARCReport` (two reports, different domains and received_at values, mixed pass/fail records), then assert:
- `DMARCSummary("", "")` returns both domains with pass/fail sums matching the seeded record counts (verify the `dkim OR spf` pass rule: a record with `dkim=fail, spf=pass` counts as pass).
- A window that excludes the older report returns only the newer domain's rows.
- `DMARCTopFailingSources("", "", 5)` returns the failing source with the right summed count and excludes sources that passed.
- `ListDMARCReports("", "", 10)` returns both, newest `received_at` first, with correct `RecordCount`, and the struct's `Raw` field left empty.

Write these as real Go test funcs (`TestDMARCSummary`, `TestDMARCTopFailingSources`, `TestListDMARCReports`) in `dmarc_test.go`, following the seeding helper pattern from Task 3.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/ -run DMARC -v`
Expected: new tests FAIL to build.

- [ ] **Step 3: Write the implementation**

```go
// DMARCDomainSummary is the per-domain rollup for the admin page. Pass/Fail
// are message counts (sums of record counts); a record passes when either
// evaluation passed — DMARC requires one aligned pass, not both.
type DMARCDomainSummary struct {
	Domain     string
	Pass, Fail int64
}

func (s *Store) DMARCSummary(from, to string) ([]DMARCDomainSummary, error) {
	rows, err := s.db.Query(`
		SELECT r.domain,
		       COALESCE(SUM(CASE WHEN rec.dkim='pass' OR rec.spf='pass' THEN rec.count ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN rec.dkim='pass' OR rec.spf='pass' THEN 0 ELSE rec.count END), 0)
		FROM dmarc_reports r JOIN dmarc_records rec ON rec.report_id = r.id
		WHERE (? = '' OR r.received_at >= ?) AND (? = '' OR r.received_at < ?)
		GROUP BY r.domain ORDER BY r.domain`, from, from, to, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DMARCDomainSummary
	for rows.Next() {
		var d DMARCDomainSummary
		if err := rows.Scan(&d.Domain, &d.Pass, &d.Fail); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type DMARCSource struct {
	SourceIP string
	Count    int64
}

func (s *Store) DMARCTopFailingSources(from, to string, limit int) ([]DMARCSource, error) {
	rows, err := s.db.Query(`
		SELECT rec.source_ip, SUM(rec.count) AS c
		FROM dmarc_reports r JOIN dmarc_records rec ON rec.report_id = r.id
		WHERE NOT (rec.dkim='pass' OR rec.spf='pass')
		  AND (? = '' OR r.received_at >= ?) AND (? = '' OR r.received_at < ?)
		GROUP BY rec.source_ip ORDER BY c DESC LIMIT ?`, from, from, to, to, limit)
	// ... scan loop identical in shape to DMARCSummary
}

type DMARCReportListItem struct {
	DMARCReport
	RecordCount int64
}

func (s *Store) ListDMARCReports(from, to string, limit int) ([]DMARCReportListItem, error) {
	rows, err := s.db.Query(`
		SELECT r.id, r.org, r.report_id, r.domain, r.range_begin, r.range_end, r.received_at,
		       (SELECT COUNT(*) FROM dmarc_records WHERE report_id = r.id)
		FROM dmarc_reports r
		WHERE (? = '' OR r.received_at >= ?) AND (? = '' OR r.received_at < ?)
		ORDER BY r.received_at DESC, r.id DESC LIMIT ?`, from, from, to, to, limit)
	// ... scan loop; Raw stays "" by design
}
```

Complete the elided scan loops in the same shape as `DMARCSummary`'s.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/`
Expected: PASS.

- [ ] **Step 5: Vet and commit**

```bash
go vet ./...
git add internal/store/dmarc.go internal/store/dmarc_test.go
git commit -m "feat(store): dmarc rollup and listing queries for the admin page"
```

---

### Task 7: admin — `/admin/dmarc` page

**Files:**
- Modify: `internal/admin/admin.go` (route in `Routes`, nav map entry, new handler)
- Create: `internal/admin/templates/dmarc.html`
- Modify: `internal/admin/templates/layout.html` (nav link after "Emails")
- Test: `internal/admin/admin_test.go` (append)

**Interfaces:**
- Consumes: Task 6's queries; the existing `resolveEmailWindow(q, now)` + `emailWindow` + period-chip machinery used by `listEmails` (reuse it — do not invent a second window resolver; read `listEmails` and `emails.html` first and mirror how chips/window state flow into the template, with base URL `/admin/dmarc`); `a.render(w, r, "dmarc", data)`; the nav map in `admin.go` (~line 136) mapping page → nav key.
- Produces: nothing — leaf task.

- [ ] **Step 1: Write the failing test**

```go
func TestDMARCPage(t *testing.T) {
	s, srv, c := adminFixture(t)
	login(t, srv, c, "hunter2")

	// Empty state.
	resp, err := c.Get(srv.URL + "/admin/dmarc")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != 200 || !strings.Contains(body, "No DMARC reports") {
		t.Fatalf("empty state: status=%d", resp.StatusCode)
	}

	// Seed one report: 11 passing + 3 failing messages for client.example.
	rep := &store.DMARCReport{Org: "google.com", ReportID: "r-1", Domain: "client.example",
		RangeBegin: "2026-08-01T00:00:00Z", RangeEnd: "2026-08-02T00:00:00Z",
		ReceivedAt: store.Now(), Raw: "<feedback/>"}
	recs := []store.DMARCRecord{
		{SourceIP: "203.0.113.7", Count: 11, DKIM: "pass", SPF: "pass"},
		{SourceIP: "198.51.100.9", Count: 3, DKIM: "fail", SPF: "fail"},
	}
	if _, _, err := s.InsertDMARCReport(rep, recs); err != nil {
		t.Fatal(err)
	}

	resp, err = c.Get(srv.URL + "/admin/dmarc")
	if err != nil {
		t.Fatal(err)
	}
	body = readBody(t, resp)
	for _, want := range []string{"client.example", "google.com", "198.51.100.9", "11", "3"} {
		if !strings.Contains(body, want) {
			t.Errorf("dmarc page missing %q", want)
		}
	}
}
```

(If the fixture's `readBody` helper has a different call shape, adapt; it exists — Task 5 of Phase 1 used it.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/admin/ -run DMARCPage -v`
Expected: FAIL — 404 on /admin/dmarc.

- [ ] **Step 3: Implement handler, route, nav, template**

Handler shape (adapt the window/chips wiring to exactly what `listEmails` does after reading it):

```go
func (a *Admin) dmarcPage(w http.ResponseWriter, r *http.Request) {
	win := resolveEmailWindow(r.URL.Query(), time.Now().UTC())
	summary, err := a.Store.DMARCSummary(win.CreatedFrom, win.CreatedTo)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	sources, _ := a.Store.DMARCTopFailingSources(win.CreatedFrom, win.CreatedTo, 10)
	reports, _ := a.Store.ListDMARCReports(win.CreatedFrom, win.CreatedTo, 100)

	// Same chip semantics as the email list (admin.go ~476): each chip is a
	// plain link carrying only its range key, so clicking one clears any
	// custom dates. This page has no other filters, so the URL is just the key.
	chips := make([]rangeChip, 0, len(emailRanges))
	for _, rg := range emailRanges {
		chips = append(chips, rangeChip{Key: rg.Key, Label: rg.Label, Title: rg.Title,
			URL: "/admin/dmarc?range=" + rg.Key, Active: win.Range == rg.Key})
	}
	a.render(w, r, "dmarc", map[string]any{
		"Ranges": chips, "RangeKey": win.Range, "WindowLabel": win.Label,
		"Summary": summary, "Sources": sources, "Reports": reports,
	})
}
```

(Read `listEmails`' chip-building block at admin.go:476-498 first and match its field usage exactly — the template keys `Ranges`/`RangeKey`/`WindowLabel` are what `emails.html`'s chip markup consumes, so `dmarc.html` can copy that markup verbatim.)

Route: `mux.Handle("GET /admin/dmarc", a.auth(a.dmarcPage))` after the emails routes. Nav map: add `"dmarc": "dmarc"`. Layout nav: `<a href="/admin/dmarc"{{if eq .Nav "dmarc"}} class="active" aria-current="page"{{end}}>DMARC</a>` after the Emails link.

Template `dmarc.html`: `{{define "content"}}` page with the period chips at top (copy the chip markup pattern from `emails.html`), then three sections using the existing `.list`/`.row`/`.row-top`/`.row-meta`/`.chip`/`.empty` classes (no tables — the codebase has none):
- **Per-domain results**: one row per `Summary` entry — domain, `N passed`, `M failed` (failed styled with the `.chip failed` pattern when M > 0).
- **Top failing sources**: rows of source IP + failing message count; omit section when empty.
- **Reports**: rows of org, domain, range begin→end, received, record count.
- Empty state (`{{else}}` on the summary list): `<p class="empty">No DMARC reports received in this period. Reports typically arrive daily once the rua address is published.</p>` — the test asserts on the leading "No DMARC reports".

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/admin/ -v`
Expected: PASS including pre-existing tests.

- [ ] **Step 5: Vet, full suite, commit**

```bash
go vet ./... && go test ./...
git add internal/admin/
git commit -m "feat(admin): DMARC reports page with per-domain rollups"
```

---

### Task 8: dkimkeys + admin — rua switch and system-domain records

**Files:**
- Modify: `internal/dkimkeys/dkimkeys.go` (`Records` signature/behavior; new `SystemRecords`)
- Modify: `internal/dkimkeys/dkimkeys_test.go` (expectations)
- Modify: `internal/admin/admin.go` (`Admin` fields + `showDomain`)
- Modify: `internal/admin/admin_test.go` (fixture + any Records-dependent assertions)
- Modify: `cmd/doevoe/main.go` and (check) `cmd/seed-demo` (callers of `admin.New` / `dkimkeys.Records` — `grep -rn "dkimkeys.Records\|admin.New" cmd/ internal/`)

**Interfaces:**
- Consumes: existing `Records`.
- Produces (used by Task 9):
  - `func Records(domain, selector, pubBase64, egressIP, dmarcRua string) []Record` — same signature, but the last parameter is now the **report address** (`dmarc@<system-domain>`), not the admin's mailbox; the DMARC record becomes `v=DMARC1; p=quarantine; rua=mailto:<dmarcRua>`.
  - `func SystemRecords(systemDomain, hostname string) []Record` — the two one-time records for the system domain: `{Type: "MX", Host: "@", Value: "10 " + hostname, Note: "Lets DMARC reporters deliver aggregate reports to doevoe's built-in receiver (port 25)."}` and `{Type: "TXT (report auth)", Host: "*._report._dmarc", Value: "v=DMARC1", Note: "RFC 7489 external-destination authorization: allows every other domain to send its DMARC reports to " + systemDomain + "."}`.
  - `Admin` gains fields `DMARCRua string` (used in `showDomain`'s `Records` call instead of `a.AdminEmail`) and `SystemDomain string`; when `d.Name == a.SystemDomain`, `showDomain` appends `SystemRecords(a.SystemDomain, a.Hostname)` to the records list. (Check whether `Admin` already stores hostname — `admin.New` takes it; find the field name and reuse.)

- [ ] **Step 1: Update tests first**

- `dkimkeys_test.go`: the existing assertion expects `rua=mailto:ops@example.com` from the adminEmail param — update the call to pass `dmarc@sys.example` and expect `rua=mailto:dmarc@sys.example`. Add `TestSystemRecords` asserting both records' Host/Value exactly as specified above.
- `admin_test.go`: the fixture calls `New(s, "hunter2", "203.0.113.7", "ops@example.com", "mail.example.com")` — after `New`, set `a.DMARCRua = "dmarc@sys.example"` and `a.SystemDomain = "sys.example"`. Add a test: create a domain named `sys.example`, GET its page, assert body contains `_report._dmarc` and `MX`; create another domain, assert its page does NOT contain `_report._dmarc` but DOES contain `rua=mailto:dmarc@sys.example`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/dkimkeys/ ./internal/admin/ -v`
Expected: FAIL (new expectations unmet).

- [ ] **Step 3: Implement**

Make the `Records`/`SystemRecords` changes; add the two `Admin` fields; in `showDomain` swap `a.AdminEmail` → `a.DMARCRua` in the `Records` call and append `SystemRecords` for the system domain. Update every caller found by the grep (main.go sets the new fields in Task 9 — for THIS task set them where `admin.New` is called so the build stays green; `cmd/seed-demo` likewise if it calls either function).

- [ ] **Step 4: Run tests, vet, full suite**

Run: `go vet ./... && go test ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/dkimkeys/ internal/admin/ cmd/
git commit -m "feat: point DMARC rua at the built-in receiver, add system-domain records"
```

---

### Task 9: config + main.go wiring, retention, docs

**Files:**
- Modify: `internal/config/config.go` + `internal/config/config_test.go` (if present — check)
- Modify: `cmd/doevoe/main.go`
- Modify: `README.md`, `.env.example`
- Modify: `docs/superpowers/specs/2026-08-01-dmarc-dnsbl-monitoring-design.md` (Status line → `**Status:** Phases 1 and 2 implemented`)

**Interfaces:**
- Consumes: everything above.
- Produces: running system.

- [ ] **Step 1: Config**

Add `InboundListen string` to `Config`. Semantics (needs `os.LookupEnv`, not `getdef`, to distinguish unset from empty):

```go
// DOEVOE_INBOUND_LISTEN is the SMTP listener for receiving DMARC aggregate
// reports. Unset → ":25". Explicitly set to "" → receiver disabled.
if v, ok := os.LookupEnv("DOEVOE_INBOUND_LISTEN"); ok {
	c.InboundListen = v
} else {
	c.InboundListen = ":25"
}
```

If `internal/config` has a test file, add cases for unset/set/empty; if not, do not create one just for this (match the package's existing test posture — check first).

- [ ] **Step 2: main.go wiring**

```go
	systemDomain := cfg.SystemFrom[strings.LastIndex(cfg.SystemFrom, "@")+1:]
	reportAddr := "dmarc@" + systemDomain
```

- Set `adm.DMARCRua = reportAddr` and `adm.SystemDomain = systemDomain` next to the other `adm.` field assignments.
- Start the receiver only when enabled. **Bind synchronously at startup** — the spec's error table says a bind failure is a misconfiguration and exits like a missing env var — then serve on the WaitGroup:

```go
	if cfg.InboundListen != "" {
		inboundListener, err := net.Listen("tcp", cfg.InboundListen)
		if err != nil {
			// Same posture as a missing required env var: the operator asked
			// for the report receiver (didn't disable it) and it can't start.
			slog.Error("inbound listen", "addr", cfg.InboundListen, "err", err)
			os.Exit(1)
		}
		inb := &inbound.Server{Store: s, ReportAddr: reportAddr, EgressIP: cfg.EgressIP,
			Hostname: cfg.Hostname, OnOwnFailure: notifier.DMARCFailure}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := inb.Serve(ctx, inboundListener); err != nil {
				slog.Error("inbound", "err", err)
			}
		}()
		slog.Info("dmarc report receiver listening", "addr", cfg.InboundListen, "rcpt", reportAddr)
	}
```

Place the bind before the other goroutines start (next to where `srv`/listeners are set up), so a failed bind exits before any background work begins.

- Retention: in `blocklistLoop`'s `run()` (it is the hourly maintenance tick), after the blocklist work, add:

```go
		if n, err := s.PruneDMARCReports(store.FmtTime(time.Now().UTC().Add(-90 * 24 * time.Hour))); err != nil {
			slog.Error("dmarc prune", "err", err)
		} else if n > 0 {
			slog.Info("dmarc prune", "reports", n)
		}
```

and update the function's doc comment to say it also owns hourly DMARC retention (or rename the loop to `hourlyMaintenanceLoop` — implementer's choice; if renaming, rename the comment references too).

- [ ] **Step 3: Verify by build + vet + full suite**

Run: `go build ./... && go vet ./... && go test ./...`
Expected: all pass. `main.go` has no test file (established precedent for wiring).

- [ ] **Step 4: Docs**

- `.env.example`: add `DOEVOE_INBOUND_LISTEN=:25` with a comment (unset = :25, empty = disabled).
- README: extend the notifications/monitoring documentation with a "DMARC reports" paragraph: doevoe receives aggregate reports on port 25 for `dmarc@<system-domain>`; the DNS records page now points every domain's `rua` there; the system domain needs the MX and `*._report._dmarc` records (shown on its domain page); reports are parsed into `/admin/dmarc` (90-day retention) and an alert fires when our own IP fails DMARC. Update the Configuration table with `DOEVOE_INBOUND_LISTEN`. Mention port 25 must be reachable from the internet (and published in the Docker docs if the README documents ports — check `docker-compose.yml` exposes it; if the compose file lists ports, add 25).
- Spec status line update.

- [ ] **Step 5: Commit**

```bash
git add internal/config/ cmd/doevoe/main.go README.md .env.example docker-compose.yml docs/superpowers/specs/2026-08-01-dmarc-dnsbl-monitoring-design.md
git commit -m "feat: wire DMARC report receiver, retention, and setup docs"
```
