package delivery

import (
	"encoding/base64"
	"fmt"
	"mime"
	"strings"

	"doevoe/internal/store"
)

// Disposition values an attachment may carry. An empty Disposition is treated
// as DispositionAttachment (that is also what the store defaults the column
// to), so callers that only want a plain file attachment can leave it unset.
const (
	DispositionAttachment = "attachment"
	DispositionInline     = "inline"
)

// maxFilenameBytes bounds an attachment filename. It is not an RFC limit —
// RFC 2231 continuations can carry arbitrarily long parameters — but a
// filename is written into a header, and a header line that runs to
// megabytes is rejected by real MTAs (RFC 5321 caps a text line at 1000
// octets) long before it is useful. 255 matches what filesystems accept and
// keeps the Content-Disposition line inside one continuation.
const maxFilenameBytes = 255

// base64LineLen is the encoded line length for attachment bodies. RFC 2045
// requires base64 lines of at most 76 characters; 76 is also a multiple of 4,
// so no line ever splits a base64 quantum.
const base64LineLen = 76

// ValidateAttachment checks everything about a that gets written into MIME
// headers: the filename and content id (both interpolated into a header
// value), the content type (parsed as a media type), and the disposition. It
// is the single authority for attachment validity, called both by
// BuildMessage — which must never write an attachment it cannot encode
// safely — and by the ingress layer (internal/send), so a bad attachment is
// rejected with a 422 at the API instead of becoming a queued email that can
// never be built. The bytes themselves are not validated: any byte sequence
// is a legal base64-encoded body.
//
// Filenames and content ids are checked for CR/LF for the same reason as
// header values generally (see validateHeaderValue): they end up inside
// Content-Disposition/Content-ID. mime.FormatMediaType would in fact
// percent-encode an embedded CRLF rather than emit it raw, but relying on
// that would make the safety of the message depend on an encoding detail of
// a parameter formatter; rejecting outright keeps it a property of the input.
func ValidateAttachment(a store.Attachment) error {
	if a.Filename == "" {
		return fmt.Errorf("attachment: filename is required")
	}
	if len(a.Filename) > maxFilenameBytes {
		return fmt.Errorf("attachment %q: filename longer than %d bytes", a.Filename, maxFilenameBytes)
	}
	if strings.ContainsAny(a.Filename, "\r\n\x00") {
		return fmt.Errorf("attachment: filename contains CR, LF or NUL")
	}
	// A filename is a name, never a path: the recipient's client decides where
	// it lands on disk, and a "../" or "/etc/passwd" in there is either an
	// attempt at that decision or a caller bug. Reject both separators rather
	// than silently rewriting the name the recipient sees.
	if strings.ContainsAny(a.Filename, `/\`) {
		return fmt.Errorf("attachment %q: filename must not contain a path separator", a.Filename)
	}
	if a.ContentType == "" {
		return fmt.Errorf("attachment %q: content_type is required", a.Filename)
	}
	mt, _, err := mime.ParseMediaType(a.ContentType)
	if err != nil {
		return fmt.Errorf("attachment %q: invalid content_type %q: %w", a.Filename, a.ContentType, err)
	}
	// Every attachment part is emitted with Content-Transfer-Encoding: base64,
	// which RFC 2045 forbids on a composite multipart type — the sub-parts of a
	// multipart must stay readable to the receiver, and a base64-wrapped one is
	// not. Nothing unsafe follows from it (the encoded body is base64 alphabet
	// only, so it cannot break out of its boundary), but it would put a
	// non-conformant part on the wire that clients handle inconsistently, so
	// reject it at ingress instead. message/* is deliberately still allowed:
	// base64 message/rfc822 is technically in the same position and universally
	// handled, and it is how a forwarded or bounced email is attached.
	if strings.HasPrefix(mt, "multipart/") {
		return fmt.Errorf("attachment %q: content_type %q is not supported; attach the parts individually",
			a.Filename, mt)
	}
	switch a.Disposition {
	case "", DispositionAttachment, DispositionInline:
	default:
		return fmt.Errorf("attachment %q: disposition must be %q or %q", a.Filename, DispositionAttachment, DispositionInline)
	}
	if a.ContentID != "" {
		if err := validateContentID(a.ContentID); err != nil {
			return fmt.Errorf("attachment %q: %w", a.Filename, err)
		}
	}
	return nil
}

// validateContentID checks the bare content id (no angle brackets: those are
// added when the header is written). RFC 2392 makes a Content-ID an addr-spec,
// so an HTML body can reference it as "cid:<id>"; rather than implement
// addr-spec, this rejects the characters that would break either the header or
// a cid: URL — whitespace and the delimiters — and requires printable ASCII.
func validateContentID(id string) error {
	if strings.ContainsAny(id, " \t\r\n<>\"") {
		return fmt.Errorf("content_id must not contain whitespace, angle brackets or quotes")
	}
	for _, r := range id {
		if r < 0x21 || r > 0x7e {
			return fmt.Errorf("content_id must be printable ASCII")
		}
	}
	return nil
}

// bodyPart is one node of the message's MIME tree: either a leaf (body set,
// children empty) or a multipart (children set, boundary set). BuildMessage
// builds a tree instead of writing MIME inline because attachments make the
// structure conditional — the same text/html body sits directly under the
// top-level headers, or inside multipart/alternative, or inside
// alternative-inside-related, or one more level down inside mixed — and
// rendering is identical at every level.
type bodyPart struct {
	contentType string      // Content-Type header value for this part
	headers     [][2]string // extra part headers, written in order after Content-Type
	body        string      // leaf body, already encoded and CRLF-terminated
	children    []bodyPart
	boundary    string
}

// writeBody writes p's body: for a leaf, the encoded bytes; for a multipart,
// each child preceded by its boundary delimiter and its own headers, then the
// closing delimiter. It does NOT write p's own Content-Type — the caller does,
// because for the root part that header belongs in the message header block
// (and gets DKIM-signed with it) rather than in the body.
func (p bodyPart) writeBody(b *strings.Builder) {
	if len(p.children) == 0 {
		b.WriteString(p.body)
		return
	}
	for _, c := range p.children {
		fmt.Fprintf(b, "--%s\r\n", p.boundary)
		fmt.Fprintf(b, "Content-Type: %s\r\n", c.contentType)
		for _, h := range c.headers {
			fmt.Fprintf(b, "%s: %s\r\n", h[0], h[1])
		}
		b.WriteString("\r\n")
		c.writeBody(b)
	}
	fmt.Fprintf(b, "--%s--\r\n", p.boundary)
}

// textLeaf renders one text/* body part. The body is CRLF-normalized (DKIM
// signs over CRLF line endings) and terminated with a CRLF of its own so the
// boundary delimiter that follows starts on a fresh line, per RFC 2046: the
// CRLF before a boundary belongs to the delimiter, not the body.
func textLeaf(contentType, body string) bodyPart {
	return bodyPart{contentType: contentType + "; charset=utf-8", body: crlf(body) + "\r\n"}
}

// multipartOf wraps children in a multipart/<subtype> part. extraParams are
// appended to the Content-Type after the boundary (multipart/related uses it
// for the required type= parameter).
func multipartOf(subtype string, children []bodyPart, extraParams ...[2]string) bodyPart {
	boundary := randHex(16)
	ct := fmt.Sprintf("multipart/%s; boundary=%q", subtype, boundary)
	for _, p := range extraParams {
		ct += fmt.Sprintf("; %s=%q", p[0], p[1])
	}
	return bodyPart{contentType: ct, children: children, boundary: boundary}
}

// attachmentLeaf renders one attachment as a base64 part. Callers must have
// run ValidateAttachment on a first.
func attachmentLeaf(a store.Attachment) (bodyPart, error) {
	disposition := a.Disposition
	if disposition == "" {
		disposition = DispositionAttachment
	}
	// FormatMediaType RFC 2231-encodes a non-ASCII filename as
	// filename*=utf-8''..., which is what modern clients read, and quotes or
	// escapes anything else that isn't a bare token. It returns "" if it cannot
	// format the result at all; treat that as an error rather than writing a
	// header with an empty value.
	cd := mime.FormatMediaType(disposition, map[string]string{"filename": a.Filename})
	if cd == "" {
		return bodyPart{}, fmt.Errorf("attachment %q: cannot format Content-Disposition", a.Filename)
	}
	headers := [][2]string{
		{"Content-Transfer-Encoding", "base64"},
		{"Content-Disposition", cd},
	}
	if a.ContentID != "" {
		// Angle brackets are added here and never stored, so a stored id is
		// always the bare form an HTML body references as "cid:<id>".
		headers = append(headers, [2]string{"Content-ID", "<" + a.ContentID + ">"})
	}
	return bodyPart{contentType: a.ContentType, headers: headers, body: base64Body(a.Content)}, nil
}

// base64Body encodes content as base64 wrapped to base64LineLen-character
// CRLF-terminated lines. Empty content yields an empty body, which is a legal
// (if pointless) zero-length part.
func base64Body(content []byte) string {
	enc := base64.StdEncoding.EncodeToString(content)
	var b strings.Builder
	b.Grow(len(enc) + 2*(len(enc)/base64LineLen+1))
	for len(enc) > base64LineLen {
		b.WriteString(enc[:base64LineLen])
		b.WriteString("\r\n")
		enc = enc[base64LineLen:]
	}
	if len(enc) > 0 {
		b.WriteString(enc)
		b.WriteString("\r\n")
	}
	return b.String()
}

// mediaType strips the parameters off a Content-Type value, e.g.
// `multipart/alternative; boundary="ab"` -> `multipart/alternative`. Used for
// multipart/related's type= parameter, which names the root part's media type
// without its parameters (RFC 2387).
func mediaType(contentType string) string {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		return strings.TrimSpace(contentType[:i])
	}
	return strings.TrimSpace(contentType)
}

// buildBody assembles the message's MIME tree from the bodies and
// attachments, from the inside out:
//
//	text only          -> text/plain
//	html only          -> text/html
//	both               -> multipart/alternative
//	+ inline parts     -> multipart/related    wrapping the above
//	+ file attachments -> multipart/mixed      wrapping the above
//
// The nesting order is what makes both cases render: multipart/related keeps
// the inline parts scoped to the body that references them by cid:, so a
// client shows them in place rather than as downloads, while multipart/mixed
// on the outside is where clients look for files to offer as attachments. An
// email with neither kind of attachment produces exactly the tree (and so the
// exact bytes) it did before attachments existed.
func buildBody(e *store.Email) (bodyPart, error) {
	var root bodyPart
	switch {
	case e.BodyText != "" && e.BodyHTML != "":
		root = multipartOf("alternative", []bodyPart{
			textLeaf("text/plain", e.BodyText),
			textLeaf("text/html", e.BodyHTML),
		})
	case e.BodyHTML != "":
		root = textLeaf("text/html", e.BodyHTML)
	default:
		root = textLeaf("text/plain", e.BodyText)
	}

	var inline, files []bodyPart
	for _, a := range e.Attachments {
		if err := ValidateAttachment(a); err != nil {
			return bodyPart{}, err
		}
		leaf, err := attachmentLeaf(a)
		if err != nil {
			return bodyPart{}, err
		}
		if a.Disposition == DispositionInline {
			inline = append(inline, leaf)
		} else {
			files = append(files, leaf)
		}
	}

	if len(inline) > 0 {
		// RFC 2387: type= names the media type of the root part, which must be
		// the first part. Both hold here — root goes in first, and its
		// contentType is read before it is nested.
		root = multipartOf("related", append([]bodyPart{root}, inline...), [2]string{"type", mediaType(root.contentType)})
	}
	if len(files) > 0 {
		root = multipartOf("mixed", append([]bodyPart{root}, files...))
	}
	return root, nil
}
