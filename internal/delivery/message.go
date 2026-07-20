package delivery

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"sort"
	"strings"
	"time"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/store"

	"github.com/emersion/go-msgauth/dkim"
)

// reservedHeaders are header names BuildMessage sets itself; custom headers
// (HeadersJSON) must not collide with them, case-insensitively, since a
// colliding custom header could shadow or duplicate a header relied on for
// routing (To/Bcc), authentication (DKIM-Signature), or MIME parsing
// (Content-Type/MIME-Version).
var reservedHeaders = map[string]bool{
	"from":           true,
	"to":             true,
	"cc":             true,
	"bcc":            true,
	"reply-to":       true,
	"subject":        true,
	"date":           true,
	"message-id":     true,
	"mime-version":   true,
	"content-type":   true,
	"dkim-signature": true,
}

// validateHeaderValue rejects raw CR/LF in a header value before it is
// interpolated into the message. Header injection via embedded "\r\n" would
// otherwise let an attacker append arbitrary headers (e.g. "Bcc: evil@...")
// that then get DKIM-signed along with the legitimate ones.
func validateHeaderValue(name, v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("header %s: value contains CR or LF", name)
	}
	return nil
}

func validateHeaderName(name string) error {
	if strings.ContainsAny(name, "\r\n") {
		return errors.New("header name contains CR or LF")
	}
	return nil
}

func BuildMessage(e *store.Email, hostname string, now time.Time) (string, error) {
	// Validate before building anything: check raw values (pre-encoding for
	// Subject) so an embedded CRLF can't sneak in via mime-encoding quirks,
	// and reject custom headers that collide with reserved names or carry
	// CR/LF, before any of it is written out and DKIM-signed.
	if err := validateHeaderValue("From", e.From); err != nil {
		return "", err
	}
	if err := validateHeaderValue("To", e.To); err != nil {
		return "", err
	}
	if e.ReplyTo != "" {
		if err := validateHeaderValue("Reply-To", e.ReplyTo); err != nil {
			return "", err
		}
	}
	if err := validateHeaderValue("Subject", e.Subject); err != nil {
		return "", err
	}

	var custom map[string]string
	if err := json.Unmarshal([]byte(e.HeadersJSON), &custom); err != nil {
		return "", fmt.Errorf("headers_json: %w", err)
	}
	keys := make([]string, 0, len(custom))
	for k := range custom {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := validateHeaderName(k); err != nil {
			return "", fmt.Errorf("headers_json: %w", err)
		}
		if reservedHeaders[strings.ToLower(k)] {
			return "", fmt.Errorf("headers_json: header %q is reserved", k)
		}
		if err := validateHeaderValue(k, custom[k]); err != nil {
			return "", fmt.Errorf("headers_json: %w", err)
		}
	}

	var b strings.Builder
	write := func(k, v string) { fmt.Fprintf(&b, "%s: %s\r\n", k, v) }

	write("From", e.From)
	write("To", e.To)
	if e.ReplyTo != "" {
		write("Reply-To", e.ReplyTo)
	}
	write("Subject", mime.QEncoding.Encode("utf-8", e.Subject))
	write("Date", now.Format(time.RFC1123Z))
	write("Message-ID", fmt.Sprintf("<%s@%s>", randHex(16), hostname))
	write("MIME-Version", "1.0")

	for _, k := range keys {
		write(k, custom[k])
	}

	switch {
	case e.BodyText != "" && e.BodyHTML != "":
		boundary := randHex(16)
		write("Content-Type", fmt.Sprintf(`multipart/alternative; boundary=%q`, boundary))
		b.WriteString("\r\n")
		part := func(ct, body string) {
			fmt.Fprintf(&b, "--%s\r\nContent-Type: %s; charset=utf-8\r\n\r\n%s\r\n", boundary, ct, crlf(body))
		}
		part("text/plain", e.BodyText)
		part("text/html", e.BodyHTML)
		fmt.Fprintf(&b, "--%s--\r\n", boundary)
	case e.BodyHTML != "":
		write("Content-Type", "text/html; charset=utf-8")
		b.WriteString("\r\n" + crlf(e.BodyHTML) + "\r\n")
	default:
		write("Content-Type", "text/plain; charset=utf-8")
		b.WriteString("\r\n" + crlf(e.BodyText) + "\r\n")
	}
	return b.String(), nil
}

func crlf(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")
}

func randHex(n int) string {
	buf := make([]byte, n)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

func SignMessage(msg string, d *store.Domain) (string, error) {
	key, err := dkimkeys.ParsePrivateKey(d.DKIMPrivateKey)
	if err != nil {
		return "", err
	}
	opts := &dkim.SignOptions{
		Domain:     d.Name,
		Selector:   d.DKIMSelector,
		Signer:     key,
		HeaderKeys: []string{"From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type"},
	}
	var out strings.Builder
	if err := dkim.Sign(&out, strings.NewReader(msg), opts); err != nil {
		return "", err
	}
	return out.String(), nil
}
