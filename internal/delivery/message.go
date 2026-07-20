package delivery

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"sort"
	"strings"
	"time"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/store"

	"github.com/emersion/go-msgauth/dkim"
)

func BuildMessage(e *store.Email, hostname string, now time.Time) (string, error) {
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
