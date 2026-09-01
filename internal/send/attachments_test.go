package send

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"doevoe/internal/delivery"
	"doevoe/internal/store"
)

func testBuildTime() time.Time { return time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC) }

// allEmails lists every email in the test DB, to assert that a rejected send
// wrote nothing.
func allEmails() store.EmailFilter { return store.EmailFilter{Limit: 100} }

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestSendStoresAttachments(t *testing.T) {
	s, d, k := setup(t, true)
	res, serr := Send(s, k.ID, d.ID, Input{
		From: "hi@example.com", To: "you@other.com", Subject: "s", HTML: `<img src="cid:logo">`,
		Attachments: []Attachment{
			{Filename: "invoice.pdf", ContentType: "application/pdf", ContentBase64: b64("%PDF fake")},
			{Filename: "logo.png", ContentType: "image/png", ContentBase64: b64("\x89PNG"),
				Disposition: "inline", ContentID: "logo"},
		},
	})
	if serr != nil {
		t.Fatalf("unexpected error: %v", serr)
	}
	e, err := s.GetEmail(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	// attachment_count rides on the email row, so the worker knows to load the
	// bytes without a second query per email.
	if e.AttachmentCount != 2 {
		t.Errorf("AttachmentCount = %d, want 2", e.AttachmentCount)
	}
	if e.Attachments != nil {
		t.Error("GetEmail must not load attachment bytes")
	}
	atts, err := s.ListAttachments(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 2 {
		t.Fatalf("got %d attachments, want 2", len(atts))
	}
	// Order is the order the caller supplied.
	if atts[0].Filename != "invoice.pdf" || atts[1].Filename != "logo.png" {
		t.Errorf("order not preserved: %q, %q", atts[0].Filename, atts[1].Filename)
	}
	if !bytes.Equal(atts[0].Content, []byte("%PDF fake")) {
		t.Errorf("content = %q, want %q", atts[0].Content, "%PDF fake")
	}
	if atts[0].Disposition != "attachment" {
		t.Errorf("default disposition = %q, want attachment", atts[0].Disposition)
	}
	if atts[1].Disposition != "inline" || atts[1].ContentID != "logo" {
		t.Errorf("inline attachment stored as %+v", atts[1])
	}
}

// TestSendGuessesContentType: omitting content_type is the common case for a
// caller that only has a filename, and application/octet-stream for a PDF
// makes some clients refuse to preview it.
func TestSendGuessesContentType(t *testing.T) {
	s, d, k := setup(t, true)
	res, serr := Send(s, k.ID, d.ID, Input{
		From: "hi@example.com", To: "you@other.com", Subject: "s", Text: "b",
		Attachments: []Attachment{
			{Filename: "notes.txt", ContentBase64: b64("hello")},
			{Filename: "data.unknown-ext", ContentBase64: b64("hello")},
		},
	})
	if serr != nil {
		t.Fatalf("unexpected error: %v", serr)
	}
	atts, _ := s.ListAttachments(res.ID)
	if !strings.HasPrefix(atts[0].ContentType, "text/plain") {
		t.Errorf("notes.txt content type = %q, want text/plain", atts[0].ContentType)
	}
	if atts[1].ContentType != "application/octet-stream" {
		t.Errorf("unknown extension content type = %q, want application/octet-stream", atts[1].ContentType)
	}
}

func TestSendAcceptsWrappedAndUnpaddedBase64(t *testing.T) {
	payload := strings.Repeat("some bytes to encode ", 20)
	std := base64.StdEncoding.EncodeToString([]byte(payload))
	wrapped := ""
	for i := 0; i < len(std); i += 60 {
		wrapped += std[i:min(i+60, len(std))] + "\r\n"
	}
	for name, encoded := range map[string]string{
		"standard": std,
		"wrapped":  wrapped,
		"unpadded": base64.RawStdEncoding.EncodeToString([]byte(payload)),
	} {
		t.Run(name, func(t *testing.T) {
			s, d, k := setup(t, true)
			res, serr := Send(s, k.ID, d.ID, Input{
				From: "hi@example.com", To: "you@other.com", Subject: "s", Text: "b",
				Attachments: []Attachment{{Filename: "a.txt", ContentType: "text/plain", ContentBase64: encoded}},
			})
			if serr != nil {
				t.Fatalf("unexpected error: %v", serr)
			}
			atts, _ := s.ListAttachments(res.ID)
			if string(atts[0].Content) != payload {
				t.Errorf("content did not round-trip (%d bytes)", len(atts[0].Content))
			}
		})
	}
}

// TestSendRejectsBadAttachmentBeforeEnqueue is the invariant the whole package
// exists for: a rejected send must leave nothing behind. An attachment that
// BuildMessage would refuse must never become a queued email that burns its
// whole retry schedule failing to build.
func TestSendRejectsBadAttachmentBeforeEnqueue(t *testing.T) {
	for _, tc := range []struct {
		name string
		att  Attachment
		code int
	}{
		{"no content", Attachment{Filename: "a.txt", ContentType: "text/plain"}, 422},
		{"not base64", Attachment{Filename: "a.txt", ContentType: "text/plain", ContentBase64: "!!!not base64!!!"}, 422},
		{"no filename", Attachment{ContentType: "text/plain", ContentBase64: b64("x")}, 422},
		{"CRLF in filename", Attachment{Filename: "a\r\nBcc: evil@example.com", ContentBase64: b64("x")}, 422},
		{"path in filename", Attachment{Filename: "../../etc/passwd", ContentBase64: b64("x")}, 422},
		{"bad content type", Attachment{Filename: "a.txt", ContentType: "not a media type", ContentBase64: b64("x")}, 422},
		{"bad disposition", Attachment{Filename: "a.txt", ContentType: "text/plain", ContentBase64: b64("x"), Disposition: "sneaky"}, 422},
		{"bad content id", Attachment{Filename: "a.txt", ContentType: "text/plain", ContentBase64: b64("x"), ContentID: "a\r\nBcc: x@y.com"}, 422},
		{"too large", Attachment{Filename: "a.bin", ContentType: "application/octet-stream",
			ContentBase64: base64.StdEncoding.EncodeToString(make([]byte, MaxAttachmentBytes+1))}, 413},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, d, k := setup(t, true)
			_, serr := Send(s, k.ID, d.ID, Input{
				From: "hi@example.com", To: "you@other.com", Subject: "s", Text: "b",
				Attachments: []Attachment{tc.att},
			})
			if serr == nil {
				t.Fatal("want an error, got nil")
			}
			if serr.Code != tc.code {
				t.Errorf("code = %d, want %d (%s)", serr.Code, tc.code, serr.Msg)
			}
			emails, _ := s.ListEmails(allEmails())
			if len(emails) != 0 {
				t.Errorf("rejected send left %d queued email(s) behind", len(emails))
			}
		})
	}
}

func TestSendRejectsTooManyAttachments(t *testing.T) {
	s, d, k := setup(t, true)
	var atts []Attachment
	for i := 0; i <= MaxAttachments; i++ {
		atts = append(atts, Attachment{Filename: "a.txt", ContentType: "text/plain", ContentBase64: b64("x")})
	}
	_, serr := Send(s, k.ID, d.ID, Input{
		From: "hi@example.com", To: "you@other.com", Subject: "s", Text: "b", Attachments: atts,
	})
	if serr == nil || serr.Code != 422 {
		t.Fatalf("want 422, got %+v", serr)
	}
}

// TestSendRejectsTooLargeTotal: each attachment is under the per-attachment
// limit, but together they exceed what a receiving MTA would accept.
func TestSendRejectsTooLargeTotal(t *testing.T) {
	s, d, k := setup(t, true)
	chunk := base64.StdEncoding.EncodeToString(make([]byte, MaxAttachmentBytes))
	var atts []Attachment
	for i := 0; i < MaxTotalAttachmentBytes/MaxAttachmentBytes+1; i++ {
		atts = append(atts, Attachment{Filename: "a.bin", ContentType: "application/octet-stream", ContentBase64: chunk})
	}
	_, serr := Send(s, k.ID, d.ID, Input{
		From: "hi@example.com", To: "you@other.com", Subject: "s", Text: "b", Attachments: atts,
	})
	if serr == nil || serr.Code != 413 {
		t.Fatalf("want 413, got %+v", serr)
	}
}

// TestSendAttachmentsBuildIntoMessage closes the loop from ingress to wire: what
// Send stored is what the delivery layer can actually build and sign.
func TestSendAttachmentsBuildIntoMessage(t *testing.T) {
	s, d, k := setup(t, true)
	res, serr := Send(s, k.ID, d.ID, Input{
		From: "hi@example.com", To: "you@other.com", Subject: "s", HTML: `<img src="cid:logo">`, Text: "b",
		Attachments: []Attachment{
			{Filename: "invoice.pdf", ContentBase64: b64("%PDF fake")},
			{Filename: "logo.png", ContentBase64: b64("\x89PNG"), Disposition: "inline", ContentID: "logo"},
		},
	})
	if serr != nil {
		t.Fatalf("unexpected error: %v", serr)
	}
	e, err := s.GetEmail(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	e.Attachments, err = s.ListAttachments(e.ID)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := delivery.BuildMessage(e, "mail.example.com", testBuildTime())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"multipart/mixed", "multipart/related", "multipart/alternative",
		"application/pdf", "image/png", "<logo>", "invoice.pdf"} {
		if !strings.Contains(msg, want) {
			t.Errorf("built message missing %q", want)
		}
	}
	// Signing is not asserted here: the test domain carries a placeholder DKIM
	// key, and the signature round-trip over a message with attachments is
	// covered in internal/delivery with a real generated keypair.
}
