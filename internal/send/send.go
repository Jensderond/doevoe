// Package send holds the shared send-email pipeline: validation, the
// idempotency pre-check, and enqueueing. Both the public JSON API and the
// MCP server call Send, so every send — regardless of surface — is fully
// validated before anything is enqueued and a queued email can never be
// permanently unsendable.
package send

import (
	"encoding/json"
	"net/mail"
	"strings"

	"doevoe/internal/delivery"
	"doevoe/internal/store"
)

type Input struct {
	From, To, Subject, HTML, Text, ReplyTo string
	Headers                                map[string]string
	IdempotencyKey                         string
}

type Result struct {
	ID     int64
	Status string
	Replay bool
}

// Error carries an HTTP-shaped status code (422/403/500) so the JSON API
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
		HeadersJSON: headersJSON, IdempotencyKey: in.IdempotencyKey,
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
