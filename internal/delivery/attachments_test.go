package delivery

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/store"

	"github.com/emersion/go-msgauth/dkim"
)

// pngBytes is a payload with high-bit bytes and an embedded CRLF, so a test
// that round-trips it proves the base64 encoding is byte-exact rather than
// merely text-safe.
var pngBytes = []byte("\x89PNG\r\n\x1a\n\x00\x01\xff\xfe binary payload")

func fileAttachment() store.Attachment {
	return store.Attachment{Filename: "invoice.pdf", ContentType: "application/pdf",
		Disposition: DispositionAttachment, Content: []byte("%PDF-1.4 fake pdf bytes")}
}

func inlineAttachment() store.Attachment {
	return store.Attachment{Filename: "logo.png", ContentType: "image/png",
		Disposition: DispositionInline, ContentID: "logo", Content: pngBytes}
}

// parsedPart is the built message parsed back into a tree, so tests can assert
// the MIME structure the way a receiving client sees it rather than by grepping
// for boundaries in a string.
type parsedPart struct {
	mediaType string
	params    map[string]string
	headers   mail.Header
	body      []byte // leaf only, transfer-decoded
	children  []parsedPart
}

// parseMessage parses a BuildMessage result. It insists on CRLF-only line
// endings first: DKIM signs the body as written, so a bare LF anywhere would
// break the signature at the recipient even though a lenient parser would
// still read the message.
func parseMessage(t *testing.T, msg string) parsedPart {
	t.Helper()
	if strings.Contains(strings.ReplaceAll(msg, "\r\n", ""), "\n") {
		t.Fatal("bare LF found; DKIM requires CRLF")
	}
	m, err := mail.ReadMessage(strings.NewReader(msg))
	if err != nil {
		t.Fatalf("parse message: %v\n%s", err, msg)
	}
	body, err := io.ReadAll(m.Body)
	if err != nil {
		t.Fatal(err)
	}
	return parsePart(t, mail.Header(m.Header), body)
}

func parsePart(t *testing.T, hdr mail.Header, body []byte) parsedPart {
	t.Helper()
	mt, params, err := mime.ParseMediaType(hdr.Get("Content-Type"))
	if err != nil {
		t.Fatalf("parse Content-Type %q: %v", hdr.Get("Content-Type"), err)
	}
	p := parsedPart{mediaType: mt, params: params, headers: hdr}
	if !strings.HasPrefix(mt, "multipart/") {
		if strings.EqualFold(hdr.Get("Content-Transfer-Encoding"), "base64") {
			// multipart.Reader decodes quoted-printable but never base64, so
			// attachment bodies are decoded here — which is also what verifies
			// the encoding is well-formed and correctly line-wrapped.
			dec, err := base64.StdEncoding.DecodeString(
				strings.NewReplacer("\r", "", "\n", "").Replace(string(body)))
			if err != nil {
				t.Fatalf("part %s: decode base64: %v", mt, err)
			}
			body = dec
		}
		p.body = body
		return p
	}
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for {
		child, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("part %s: next part: %v", mt, err)
		}
		cb, err := io.ReadAll(child)
		if err != nil {
			t.Fatal(err)
		}
		p.children = append(p.children, parsePart(t, mail.Header(child.Header), cb))
	}
	return p
}

// tree renders the parsed structure as indented media types, which is what the
// structural assertions compare against.
func (p parsedPart) tree() string {
	var b strings.Builder
	p.writeTree(&b, 0)
	return b.String()
}

func (p parsedPart) writeTree(b *strings.Builder, depth int) {
	fmt.Fprintf(b, "%s%s\n", strings.Repeat("  ", depth), p.mediaType)
	for _, c := range p.children {
		c.writeTree(b, depth+1)
	}
}

// find returns the first part with the given media type, depth-first.
func (p parsedPart) find(mediaType string) (parsedPart, bool) {
	if p.mediaType == mediaType {
		return p, true
	}
	for _, c := range p.children {
		if got, ok := c.find(mediaType); ok {
			return got, true
		}
	}
	return parsedPart{}, false
}

// TestBuildMessageNoAttachmentsStructureUnchanged pins the pre-attachment
// shape: an email without attachments must not gain a multipart/mixed wrapper,
// since every existing message would otherwise change structure (and its DKIM
// body hash) for nothing.
func TestBuildMessageNoAttachmentsStructureUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name, text, html, want string
	}{
		{"text only", "plain", "", "text/plain\n"},
		{"html only", "", "<b>hi</b>", "text/html\n"},
		{"both", "plain", "<b>hi</b>", "multipart/alternative\n  text/plain\n  text/html\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi",
				BodyText: tc.text, BodyHTML: tc.html, HeadersJSON: "{}"}
			msg, err := BuildMessage(e, "mail.example.com", testTime)
			if err != nil {
				t.Fatal(err)
			}
			if got := parseMessage(t, msg).tree(); got != tc.want {
				t.Errorf("structure:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

func TestBuildMessageFileAttachment(t *testing.T) {
	att := fileAttachment()
	e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi",
		BodyText: "plain", BodyHTML: "<b>hi</b>", HeadersJSON: "{}",
		AttachmentCount: 1, Attachments: []store.Attachment{att}}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		t.Fatal(err)
	}
	root := parseMessage(t, msg)
	want := "multipart/mixed\n  multipart/alternative\n    text/plain\n    text/html\n  application/pdf\n"
	if got := root.tree(); got != want {
		t.Fatalf("structure:\n%s\nwant:\n%s", got, want)
	}
	// The top-level Content-Type must be the mixed one: it is a message header,
	// so it is what DKIM signs and what the recipient parses first.
	if !strings.Contains(msg, "Content-Type: multipart/mixed;") {
		t.Error("top-level Content-Type is not multipart/mixed")
	}
	pdf := root.children[1]
	if !bytes.Equal(pdf.body, att.Content) {
		t.Errorf("attachment body = %q, want %q", pdf.body, att.Content)
	}
	if got := pdf.headers.Get("Content-Transfer-Encoding"); got != "base64" {
		t.Errorf("Content-Transfer-Encoding = %q, want base64", got)
	}
	disp, params, err := mime.ParseMediaType(pdf.headers.Get("Content-Disposition"))
	if err != nil {
		t.Fatal(err)
	}
	if disp != "attachment" || params["filename"] != "invoice.pdf" {
		t.Errorf("Content-Disposition = %q %v, want attachment/invoice.pdf", disp, params)
	}
}

// TestBuildMessageInlineImage covers the case transactional mail actually
// wants: an image referenced from the HTML body by cid:, which has to sit in a
// multipart/related alongside the body rather than in a multipart/mixed, or
// clients offer it as a download instead of rendering it in place.
func TestBuildMessageInlineImage(t *testing.T) {
	e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi",
		BodyHTML: `<img src="cid:logo">`, HeadersJSON: "{}",
		AttachmentCount: 1, Attachments: []store.Attachment{inlineAttachment()}}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		t.Fatal(err)
	}
	root := parseMessage(t, msg)
	want := "multipart/related\n  text/html\n  image/png\n"
	if got := root.tree(); got != want {
		t.Fatalf("structure:\n%s\nwant:\n%s", got, want)
	}
	// RFC 2387: multipart/related names its root part's media type, and the
	// root part comes first.
	if got := root.params["type"]; got != "text/html" {
		t.Errorf(`multipart/related type= %q, want "text/html"`, got)
	}
	img := root.children[1]
	// The stored id is bare; the header form is angle-bracketed, which is what
	// a "cid:logo" reference in the HTML resolves against.
	if got := img.headers.Get("Content-ID"); got != "<logo>" {
		t.Errorf("Content-ID = %q, want <logo>", got)
	}
	if got := img.headers.Get("Content-Disposition"); !strings.HasPrefix(got, "inline") {
		t.Errorf("Content-Disposition = %q, want inline", got)
	}
	if !bytes.Equal(img.body, pngBytes) {
		t.Errorf("inline body = %q, want %q", img.body, pngBytes)
	}
}

// TestBuildMessageInlineAndFileAttachment is the full nesting: mixed wrapping
// related wrapping alternative. Getting the order wrong (mixed inside related)
// makes clients either hide the file attachment or stop rendering the inline
// image, so the exact tree is the assertion.
func TestBuildMessageInlineAndFileAttachment(t *testing.T) {
	e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi",
		BodyText: "plain", BodyHTML: `<img src="cid:logo">`, HeadersJSON: "{}",
		AttachmentCount: 2, Attachments: []store.Attachment{inlineAttachment(), fileAttachment()}}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		t.Fatal(err)
	}
	root := parseMessage(t, msg)
	want := "multipart/mixed\n" +
		"  multipart/related\n" +
		"    multipart/alternative\n" +
		"      text/plain\n" +
		"      text/html\n" +
		"    image/png\n" +
		"  application/pdf\n"
	if got := root.tree(); got != want {
		t.Fatalf("structure:\n%s\nwant:\n%s", got, want)
	}
	related, _ := root.find("multipart/related")
	if got := related.params["type"]; got != "multipart/alternative" {
		t.Errorf(`multipart/related type= %q, want "multipart/alternative"`, got)
	}
	// Every multipart level must use its own boundary, or a nested closing
	// delimiter would terminate the wrong level and truncate the message.
	alt, _ := root.find("multipart/alternative")
	boundaries := map[string]bool{}
	for _, b := range []string{root.params["boundary"], related.params["boundary"], alt.params["boundary"]} {
		if b == "" {
			t.Fatal("multipart without a boundary parameter")
		}
		if boundaries[b] {
			t.Fatalf("nested multiparts share the boundary %q", b)
		}
		boundaries[b] = true
	}
}

// TestBuildMessageMultipleAttachmentsKeepOrder: the store returns attachments
// in insertion order, and the message must preserve it — a caller listing
// "page1.pdf, page2.pdf" means that order.
func TestBuildMessageMultipleAttachmentsKeepOrder(t *testing.T) {
	var atts []store.Attachment
	for i := 1; i <= 3; i++ {
		atts = append(atts, store.Attachment{Filename: fmt.Sprintf("page%d.txt", i),
			ContentType: "text/plain", Content: []byte(fmt.Sprintf("body %d", i))})
	}
	e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi", BodyText: "x",
		HeadersJSON: "{}", AttachmentCount: len(atts), Attachments: atts}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		t.Fatal(err)
	}
	root := parseMessage(t, msg)
	if len(root.children) != 4 {
		t.Fatalf("got %d parts, want 4 (body + 3 attachments)", len(root.children))
	}
	for i, c := range root.children[1:] {
		_, params, _ := mime.ParseMediaType(c.headers.Get("Content-Disposition"))
		if want := fmt.Sprintf("page%d.txt", i+1); params["filename"] != want {
			t.Errorf("part %d filename = %q, want %q", i+1, params["filename"], want)
		}
	}
}

// TestBuildMessageBase64LineLength: RFC 2045 caps an encoded line at 76
// characters, and RFC 5321 rejects any line over 1000 octets outright, so a
// large attachment emitted as one long line would be undeliverable.
func TestBuildMessageBase64LineLength(t *testing.T) {
	content := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64KB
	e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi", BodyText: "x",
		HeadersJSON: "{}", AttachmentCount: 1,
		Attachments: []store.Attachment{{Filename: "big.bin", ContentType: "application/octet-stream", Content: content}}}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(msg, "\r\n") {
		if len(line) > base64LineLen {
			t.Fatalf("line of %d chars exceeds %d: %.80q", len(line), base64LineLen, line)
		}
	}
	root := parseMessage(t, msg)
	if !bytes.Equal(root.children[1].body, content) {
		t.Error("64KB attachment did not round-trip")
	}
}

func TestBuildMessageEmptyAttachmentContent(t *testing.T) {
	e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi", BodyText: "x",
		HeadersJSON: "{}", AttachmentCount: 1,
		Attachments: []store.Attachment{{Filename: "empty.txt", ContentType: "text/plain"}}}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		t.Fatal(err)
	}
	root := parseMessage(t, msg)
	if len(root.children) != 2 || len(root.children[1].body) != 0 {
		t.Errorf("zero-length attachment should produce an empty part, got %d parts\n%s", len(root.children), msg)
	}
}

// TestBuildMessageEncodesNonASCIIFilename: a filename is a header parameter,
// so non-ASCII needs RFC 2231 encoding (filename*=utf-8”...) — raw UTF-8 in a
// header is what makes a client show mojibake or drop the name entirely.
func TestBuildMessageEncodesNonASCIIFilename(t *testing.T) {
	e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi", BodyText: "x",
		HeadersJSON: "{}", AttachmentCount: 1,
		Attachments: []store.Attachment{{Filename: "faktura-übersicht.pdf", ContentType: "application/pdf",
			Content: []byte("x")}}}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg, "übersicht") {
		t.Error("non-ASCII filename must be RFC 2231-encoded, found raw UTF-8")
	}
	if !strings.Contains(msg, "filename*=utf-8''") {
		t.Errorf("expected RFC 2231 filename* parameter\n%s", msg)
	}
	// And it must decode back to the original: mime.ParseMediaType is what a
	// receiving client does.
	root := parseMessage(t, msg)
	_, params, err := mime.ParseMediaType(root.children[1].headers.Get("Content-Disposition"))
	if err != nil {
		t.Fatal(err)
	}
	if params["filename"] != "faktura-übersicht.pdf" {
		t.Errorf("decoded filename = %q, want %q", params["filename"], "faktura-übersicht.pdf")
	}
}

// TestBuildMessageRejectsAttachmentsNotLoaded guards the split between the
// emails row and email_attachments: a caller that skipped ListAttachments must
// get an error, never a message quietly missing its attachments.
func TestBuildMessageRejectsAttachmentsNotLoaded(t *testing.T) {
	e := &store.Email{ID: 7, From: "a@example.com", To: "b@dest.test", Subject: "Hi",
		BodyText: "plain", HeadersJSON: "{}", AttachmentCount: 2}
	_, err := BuildMessage(e, "mail.example.com", testTime)
	if err == nil {
		t.Fatal("want error when attachment_count > 0 and none loaded, got nil")
	}
	if !strings.Contains(err.Error(), "none were loaded") {
		t.Errorf("error %q should say the attachments were not loaded", err)
	}
}

func TestBuildMessageRejectsInvalidAttachment(t *testing.T) {
	for _, tc := range []struct {
		name string
		att  store.Attachment
	}{
		{"no filename", store.Attachment{ContentType: "text/plain", Content: []byte("x")}},
		{"CRLF in filename", store.Attachment{Filename: "a\r\nBcc: evil@example.com", ContentType: "text/plain", Content: []byte("x")}},
		{"LF in filename", store.Attachment{Filename: "a\nb.txt", ContentType: "text/plain", Content: []byte("x")}},
		{"NUL in filename", store.Attachment{Filename: "a\x00b.txt", ContentType: "text/plain", Content: []byte("x")}},
		{"path in filename", store.Attachment{Filename: "../../etc/passwd", ContentType: "text/plain", Content: []byte("x")}},
		{"backslash in filename", store.Attachment{Filename: `..\win.ini`, ContentType: "text/plain", Content: []byte("x")}},
		{"overlong filename", store.Attachment{Filename: strings.Repeat("a", maxFilenameBytes+1) + ".txt", ContentType: "text/plain", Content: []byte("x")}},
		{"no content type", store.Attachment{Filename: "a.txt", Content: []byte("x")}},
		{"unparseable content type", store.Attachment{Filename: "a.txt", ContentType: "not a media type", Content: []byte("x")}},
		{"CRLF in content type", store.Attachment{Filename: "a.txt", ContentType: "text/plain\r\nBcc: evil@example.com", Content: []byte("x")}},
		{"bad disposition", store.Attachment{Filename: "a.txt", ContentType: "text/plain", Disposition: "sneaky", Content: []byte("x")}},
		{"multipart content type", store.Attachment{Filename: "a.eml", ContentType: `multipart/mixed; boundary="x"`, Content: []byte("x")}},
		{"CRLF in content id", store.Attachment{Filename: "a.txt", ContentType: "text/plain", ContentID: "a\r\nBcc: evil@example.com", Content: []byte("x")}},
		{"angle brackets in content id", store.Attachment{Filename: "a.txt", ContentType: "text/plain", ContentID: "<logo>", Content: []byte("x")}},
		{"space in content id", store.Attachment{Filename: "a.txt", ContentType: "text/plain", ContentID: "a logo", Content: []byte("x")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateAttachment(tc.att); err == nil {
				t.Error("ValidateAttachment: want error, got nil")
			}
			e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi", BodyText: "plain",
				HeadersJSON: "{}", AttachmentCount: 1, Attachments: []store.Attachment{tc.att}}
			msg, err := BuildMessage(e, "mail.example.com", testTime)
			if err == nil {
				t.Errorf("BuildMessage: want error, got nil\n%s", msg)
			}
		})
	}
}

func TestValidateAttachmentAccepts(t *testing.T) {
	for _, att := range []store.Attachment{
		fileAttachment(),
		inlineAttachment(),
		{Filename: "a.txt", ContentType: "text/plain"},                                // empty content is a legal part
		{Filename: "a.txt", ContentType: "text/plain; charset=utf-8"},                 // parameters are fine
		{Filename: "faktura-übersicht.pdf", ContentType: "application/pdf"},           // encoded on the way out
		{Filename: "a.txt", ContentType: "text/plain", Disposition: ""},               // defaults to attachment
		{Filename: "a.txt", ContentType: "text/plain", ContentID: "logo@example.com"}, // addr-spec form
		{Filename: "forwarded.eml", ContentType: "message/rfc822"},                    // attaching an email is allowed
		{Filename: strings.Repeat("a", maxFilenameBytes-4) + ".txt", ContentType: "text/plain"},
	} {
		if err := ValidateAttachment(att); err != nil {
			t.Errorf("ValidateAttachment(%q): %v", att.Filename, err)
		}
	}
}

// TestBuildMessageRejectsReservedMIMEPartHeaders: the Content-* part headers
// BuildMessage now writes itself must be reserved like Content-Type was, or a
// custom header could tell the recipient to base64-decode a multipart body.
func TestBuildMessageRejectsReservedMIMEPartHeaders(t *testing.T) {
	for _, name := range []string{"Content-Transfer-Encoding", "content-transfer-encoding",
		"Content-Disposition", "Content-ID"} {
		e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi", BodyText: "plain",
			HeadersJSON: fmt.Sprintf(`{%q:"base64"}`, name)}
		if _, err := BuildMessage(e, "mail.example.com", testTime); err == nil {
			t.Errorf("header %q: want error for reserved custom header, got nil", name)
		}
		if err := ValidateHeader(name, "base64"); err == nil {
			t.Errorf("header %q: ValidateHeader should reject it at ingress too", name)
		}
	}
}

// TestSignMessageWithAttachmentsVerifies is the end of the pipeline: a message
// with attachments must still produce a DKIM signature that verifies, which is
// what catches any body canonicalization mistake (a stray bare LF, a missing
// CRLF before a boundary) that the structural tests would let through.
func TestSignMessageWithAttachmentsVerifies(t *testing.T) {
	priv, _, err := dkimkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	d := &store.Domain{Name: "example.com", DKIMSelector: "mail1", DKIMPrivateKey: priv}
	e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi",
		BodyText: "plain", BodyHTML: `<img src="cid:logo">`, HeadersJSON: "{}",
		AttachmentCount: 2, Attachments: []store.Attachment{inlineAttachment(), fileAttachment()}}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignMessage(msg, d)
	if err != nil {
		t.Fatal(err)
	}
	verifications, err := dkim.VerifyWithOptions(strings.NewReader(signed), &dkim.VerifyOptions{
		LookupTXT: func(name string) ([]string, error) {
			key, _ := dkimkeys.ParsePrivateKey(priv)
			pub, _ := dkimkeys.PublicKeyTXT(&key.PublicKey)
			return []string{pub}, nil
		},
	})
	if err != nil || len(verifications) != 1 || verifications[0].Err != nil {
		t.Fatalf("verify: %v %+v", err, verifications)
	}
	// The signed message must still parse, with the attachments intact: DKIM
	// prepends a header, it must not disturb the body.
	root := parseMessage(t, signed)
	if _, ok := root.find("application/pdf"); !ok {
		t.Error("signed message lost its attachment")
	}
}
