package dmarcreport

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
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
	// A ~10MB-of-zeros gzip is tiny compressed; extraction must stop at
	// MaxXMLBytes (5MB) instead of inflating it all.
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte{0}, 1<<20)
	for i := 0; i < 10; i++ {
		gw.Write(chunk)
	}
	gw.Close()
	msg := "From: a@b\r\nMIME-Version: 1.0\r\nContent-Type: application/gzip\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + b64(buf.Bytes())
	if _, err := FromEmail(strings.NewReader(msg)); err == nil {
		t.Fatal("expected decompression-cap error")
	}
}

// wrapBase64 wraps base64 text at 76 characters with CRLF line endings,
// mimicking standard SMTP text encoding.
func wrapBase64(s string) string {
	var result strings.Builder
	for i := 0; i < len(s); i += 76 {
		end := i + 76
		if end > len(s) {
			end = len(s)
		}
		result.WriteString(s[i:end])
		result.WriteString("\r\n")
	}
	return result.String()
}

func TestFromEmailBase64LineWrapping(t *testing.T) {
	// Test that lineStripper correctly handles CRLF-wrapped base64.
	// Standard SMTP wraps base64 at 76 chars; this ensures our
	// Content-Transfer-Encoding: base64 decoding handles real-world wrapping.
	gzipped := gzipBytes(t, tinyXML)
	encoded := b64(gzipped)
	wrapped := wrapBase64(encoded)
	msg := "From: a@b\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: application/gzip\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + wrapped
	got, err := FromEmail(strings.NewReader(msg))
	if err != nil || string(got) != tinyXML {
		t.Errorf("wrapped base64: err=%v, got %d bytes expected %d", err, len(got), len(tinyXML))
	}
}

func TestFromEmailNestedMultipart(t *testing.T) {
	// Test multipart/alternative with a nested multipart/mixed inside,
	// where the actual report attachment lives in the nested part.
	// This structure is common with email clients.
	var outerBody bytes.Buffer
	outerMW := multipart.NewWriter(&outerBody)
	defer outerMW.Close()

	// Add a text/plain part to the outer multipart/alternative
	h := textproto.MIMEHeader{}
	h.Set("Content-Type", "text/plain; charset=us-ascii")
	p, _ := outerMW.CreatePart(h)
	p.Write([]byte("This is a text version of the report."))

	// Create a nested multipart/mixed with its own boundary
	h = textproto.MIMEHeader{}
	h.Set("Content-Type", "multipart/mixed")
	innerBoundary := "inner-" + outerMW.Boundary()
	h.Set("Content-Type", "multipart/mixed; boundary="+innerBoundary)
	p, _ = outerMW.CreatePart(h)

	// Write the nested multipart manually with the custom boundary
	innerWriter := multipart.NewWriter(p)
	innerWriter.SetBoundary(innerBoundary)

	// Add a text part to the inner multipart
	h = textproto.MIMEHeader{}
	h.Set("Content-Type", "text/plain")
	ip, _ := innerWriter.CreatePart(h)
	ip.Write([]byte("Nested text part."))

	// Add the gzip report to the inner multipart
	h = textproto.MIMEHeader{}
	h.Set("Content-Type", "application/gzip")
	h.Set("Content-Disposition", `attachment; filename="report.xml.gz"`)
	h.Set("Content-Transfer-Encoding", "base64")
	ip, _ = innerWriter.CreatePart(h)
	ip.Write([]byte(b64(gzipBytes(t, tinyXML))))
	innerWriter.Close()

	// Build the outer message
	msg := "From: a@b\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/alternative; boundary=" + outerMW.Boundary() + "\r\n\r\n" +
		outerBody.String()

	got, err := FromEmail(strings.NewReader(msg))
	if err != nil || string(got) != tinyXML {
		t.Fatalf("nested multipart: err=%v, got %d bytes expected %d", err, len(got), len(tinyXML))
	}
}

func TestFromEmailZipDecompressionCap(t *testing.T) {
	// Mirror TestFromEmailDecompressionCap but with a zip containing a huge .xml entry.
	// A ~10MB XML file in a zip is tiny compressed; extraction must stop at
	// MaxXMLBytes (5MB) instead of inflating it all.
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	f, _ := zw.Create("huge.xml")
	chunk := bytes.Repeat([]byte{0}, 1<<20)
	for i := 0; i < 10; i++ {
		f.Write(chunk)
	}
	zw.Close()

	msg := "From: a@b\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: application/zip\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + b64(zipBuf.Bytes())
	if _, err := FromEmail(strings.NewReader(msg)); err == nil {
		t.Fatal("expected zip decompression-cap error")
	}
}
