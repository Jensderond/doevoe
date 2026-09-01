// Package send holds the shared send-email pipeline: validation, the
// idempotency pre-check, and enqueueing. Both the public JSON API and the
// MCP server call Send, so every send — regardless of surface — is fully
// validated before anything is enqueued and a queued email can never be
// permanently unsendable.
package send

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net/mail"
	"path/filepath"
	"strings"

	"doevoe/internal/delivery"
	"doevoe/internal/store"
)

type Input struct {
	From, To, Subject, HTML, Text, ReplyTo string
	Headers                                map[string]string
	Attachments                            []Attachment
	IdempotencyKey                         string
}

// Attachment is one attachment as it arrives on the wire. ContentBase64 is
// deliberately the base64 text rather than raw bytes: both surfaces (JSON API
// and MCP) carry it that way, so decoding it here — once — is what keeps the
// decode, the size accounting and the limit checks in a single place instead
// of duplicated at each edge. store.Attachment holds the decoded bytes.
type Attachment struct {
	Filename      string
	ContentType   string
	ContentBase64 string
	// Disposition is "attachment" (the default) or "inline". An inline
	// attachment with a ContentID is what an HTML body references as
	// "cid:<ContentID>", e.g. <img src="cid:logo">.
	Disposition string
	ContentID   string
}

// Attachment limits. These are the real per-message ceiling, and they are set
// from what receiving MTAs accept rather than from what this process could
// hold: base64 inflates the payload by 4/3 on the wire and again in the built
// message, so MaxTotalAttachmentBytes of 15MB of actual file data becomes
// ~20.5MB of message — comfortably under the ~25MB total-message limit most
// large mailbox providers enforce (and which they reject with a permanent
// 5xx, so a too-large message is a wasted send, not a retry). The request
// body cap at the API edge (api.maxRequestBodyBytes) has to be large enough
// to hold the base64 form of this plus the bodies and headers, and is derived
// from these numbers.
//
// MaxAttachments bounds the part count independently: 20 parts of a few
// kilobytes each is far below the byte caps but already an unusual
// transactional email, and each part costs a header block and a row.
const (
	MaxAttachments          = 20
	MaxAttachmentBytes      = 10 << 20 // per attachment, decoded
	MaxTotalAttachmentBytes = 15 << 20 // all attachments in one email, decoded
)

type Result struct {
	ID     int64
	Status string
	Replay bool
}

// Error carries an HTTP-shaped status code (422/413/403/500) so the JSON API
// can map it directly and the MCP surface can use Msg as the tool error.
type Error struct {
	Code int
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

// Send validates in, applies the idempotency pre-check scoped to apiKeyID,
// and enqueues the email on the domain identified by domainID. apiKeyID is
// 0 for admin/MCP-originated sends (same convention as system
// notifications); it scopes idempotency keys and attributes the email to
// the key in the admin UI. The validation order (and every error message)
// is load-bearing: internal/api's tests assert them, and validation must
// complete before any row is written.
func Send(st *store.Store, apiKeyID, domainID int64, in Input) (Result, *Error) {
	from, err := mail.ParseAddress(in.From)
	if err != nil {
		return Result{}, &Error{422, "invalid from address"}
	}
	to, err := mail.ParseAddress(in.To)
	if err != nil {
		return Result{}, &Error{422, "invalid to address"}
	}
	if in.Subject == "" || (in.HTML == "" && in.Text == "") {
		return Result{}, &Error{422, "subject and html or text are required"}
	}
	// Validate ingress input that the delivery layer would otherwise only catch
	// at send time (see delivery.BuildMessage), which would leave a queued email
	// that can never send. Reject it immediately instead.
	if err := delivery.ValidateHeaderValue("Subject", in.Subject); err != nil {
		return Result{}, &Error{422, "invalid subject: " + err.Error()}
	}
	if in.ReplyTo != "" {
		if _, err := mail.ParseAddress(in.ReplyTo); err != nil {
			return Result{}, &Error{422, "invalid reply_to address"}
		}
	}
	if err := delivery.ValidateHeaderValue("From", delivery.FormatAddress(from.Name, from.Address)); err != nil {
		return Result{}, &Error{422, "invalid from: " + err.Error()}
	}
	if err := delivery.ValidateHeaderValue("To", delivery.FormatAddress(to.Name, to.Address)); err != nil {
		return Result{}, &Error{422, "invalid to: " + err.Error()}
	}
	for name, value := range in.Headers {
		if err := delivery.ValidateHeader(name, value); err != nil {
			return Result{}, &Error{422, "invalid header: " + err.Error()}
		}
	}
	attachments, aerr := decodeAttachments(in.Attachments)
	if aerr != nil {
		return Result{}, aerr
	}
	domain, err := st.GetDomain(domainID)
	if err != nil {
		return Result{}, &Error{500, "internal error"}
	}
	fromDomain := from.Address[strings.LastIndex(from.Address, "@")+1:]
	if !strings.EqualFold(fromDomain, domain.Name) {
		return Result{}, &Error{422, "from address must be on domain " + domain.Name}
	}
	if !domain.Verified() {
		return Result{}, &Error{403, "domain " + domain.Name + " is not verified; complete DNS setup in the doevoe admin before sending"}
	}

	if in.IdempotencyKey != "" {
		if existing, err := st.FindByIdempotencyKey(apiKeyID, in.IdempotencyKey); err == nil && existing != nil {
			return Result{ID: existing.ID, Status: existing.Status, Replay: true}, nil
		}
	}

	headersJSON := "{}"
	if len(in.Headers) > 0 {
		hb, _ := json.Marshal(in.Headers)
		headersJSON = string(hb)
	}
	id, status, replay, err := enqueueOrReplay(st, &store.Email{
		APIKeyID: apiKeyID, DomainID: domain.ID,
		From: from.Address, To: to.Address, FromName: from.Name, ToName: to.Name, ReplyTo: in.ReplyTo,
		Subject: in.Subject, BodyHTML: in.HTML, BodyText: in.Text,
		HeadersJSON: headersJSON, Attachments: attachments, IdempotencyKey: in.IdempotencyKey,
	})
	if err != nil {
		return Result{}, &Error{500, "enqueue failed"}
	}
	return Result{ID: id, Status: status, Replay: replay}, nil
}

// enqueueOrReplay inserts e via store.EnqueueEmail. A caller-supplied
// Idempotency-Key is already checked once by Send before this is
// called (FindByIdempotencyKey), but that check-then-insert is not atomic:
// a racing duplicate request can insert the same (api_key_id,
// idempotency_key) pair in between, and the partial unique index
// idx_emails_idem then causes this insert to fail. Rather than surface that
// as a bare 500 for what is really a successful, idempotent replay, this
// re-checks FindByIdempotencyKey on insert failure and, if a matching row
// now exists, returns it as a replay (200) instead of an error. If no
// matching row is found, or no idempotency key was supplied, the original
// insert error is returned unchanged.
func enqueueOrReplay(st *store.Store, e *store.Email) (id int64, status string, replay bool, err error) {
	id, err = st.EnqueueEmail(e)
	if err == nil {
		return id, "queued", false, nil
	}
	if e.IdempotencyKey != "" {
		if existing, ferr := st.FindByIdempotencyKey(e.APIKeyID, e.IdempotencyKey); ferr == nil && existing != nil {
			return existing.ID, existing.Status, true, nil
		}
	}
	return 0, "", false, err
}

// decodeAttachments turns wire attachments into store attachments: it decodes
// the base64, fills in a content type when the caller left it out, enforces
// the count and size limits, and runs delivery.ValidateAttachment — the same
// check BuildMessage runs — on each one. Like every other check in Send this
// happens before the domain lookup and before anything is written, so an
// unencodable attachment is a 422 at the API rather than a queued email that
// BuildMessage would refuse for the rest of its retry schedule.
func decodeAttachments(in []Attachment) ([]store.Attachment, *Error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > MaxAttachments {
		return nil, &Error{422, fmt.Sprintf("too many attachments: %d (max %d)", len(in), MaxAttachments)}
	}
	out := make([]store.Attachment, 0, len(in))
	var total int
	for i, a := range in {
		// Identify the attachment by name where there is one, by position
		// otherwise, so an error about the third of five is actionable.
		label := fmt.Sprintf("attachment %d", i+1)
		if a.Filename != "" {
			label = fmt.Sprintf("attachment %q", a.Filename)
		}
		if a.ContentBase64 == "" {
			return nil, &Error{422, label + ": content is required"}
		}
		content, err := decodeBase64(a.ContentBase64)
		if err != nil {
			return nil, &Error{422, label + ": content is not valid base64"}
		}
		if len(content) > MaxAttachmentBytes {
			return nil, &Error{413, fmt.Sprintf("%s: %d bytes exceeds the %d byte per-attachment limit",
				label, len(content), MaxAttachmentBytes)}
		}
		total += len(content)
		if total > MaxTotalAttachmentBytes {
			return nil, &Error{413, fmt.Sprintf("attachments total more than the %d byte per-message limit",
				MaxTotalAttachmentBytes)}
		}
		sa := store.Attachment{
			Filename:    a.Filename,
			ContentType: a.ContentType,
			Disposition: a.Disposition,
			ContentID:   a.ContentID,
			Content:     content,
		}
		if sa.ContentType == "" {
			sa.ContentType = guessContentType(a.Filename)
		}
		if sa.Disposition == "" {
			sa.Disposition = delivery.DispositionAttachment
		}
		if err := delivery.ValidateAttachment(sa); err != nil {
			return nil, &Error{422, err.Error()}
		}
		out = append(out, sa)
	}
	return out, nil
}

// decodeBase64 accepts the base64 a client is likely to send: standard
// alphabet, with or without padding, and with or without the line breaks that
// MIME-style encoders (and pretty-printed JSON fixtures) insert. Whitespace is
// stripped before decoding rather than rejected, since a wrapped payload is
// well-formed base64 by RFC 2045's reckoning and rejecting it would be a
// gratuitous incompatibility.
func decodeBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// guessContentType fills in a content type the caller omitted, from the
// filename extension. The fallback is application/octet-stream, which is what
// RFC 2046 prescribes for "unrecognized" data and makes a client offer the
// file as a download instead of trying to render it.
func guessContentType(filename string) string {
	if ct := mime.TypeByExtension(filepath.Ext(filename)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}
