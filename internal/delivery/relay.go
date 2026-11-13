package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"doevoe/internal/store"
)

// Route returns a SendFunc that picks the last hop per domain: relay for a
// domain set to an external provider (store.Domain.Relayed), direct
// otherwise. The worker neither knows nor cares which ran — both report a
// Result, and Classify understands both kinds of error.
func Route(direct, relay SendFunc) SendFunc {
	return func(ctx context.Context, e *store.Email, d *store.Domain) Result {
		if d.Relayed() {
			return relay(ctx, e, d)
		}
		return direct(ctx, e, d)
	}
}

// emailEUEndpoint is email.eu's send endpoint. The request and response
// shapes below follow its published spec
// (https://send.email.eu/api/v1/openapi.json, NewMessage / Taken / Error).
const emailEUEndpoint = "https://send.email.eu/api/v1/send"

// relayTimeout bounds one whole HTTP exchange with the provider, upload of
// the attachments included. Like the direct sender's OverallTimeout it has to
// stay far below the worker's staleSendingWindow (worker.go), or a slow
// request could be requeued and sent a second time while the first is still
// in flight. The Idempotency-Key below makes that harmless on the provider's
// side too, but only for a day and only as a second line of defence.
const relayTimeout = 2 * time.Minute

// maxRelayResponseBytes caps how much of a response body is read: the
// provider's answers are a few hundred bytes of JSON, and whatever is read
// ends up in the attempt log.
const maxRelayResponseBytes = 64 << 10

// RelayError is a non-2xx answer from a provider's HTTP API. Status is the
// HTTP status; Code and Message are the provider's own error fields when the
// body carried them.
type RelayError struct {
	Status        int
	Code, Message string
}

func (e *RelayError) Error() string {
	switch {
	case e.Code != "" && e.Message != "":
		return fmt.Sprintf("email.eu %d %s: %s", e.Status, e.Code, e.Message)
	case e.Message != "":
		return fmt.Sprintf("email.eu %d: %s", e.Status, e.Message)
	}
	return fmt.Sprintf("email.eu answered %d", e.Status)
}

// Permanent reports whether retrying the identical request is pointless.
//
// That is true of a 4xx that judges the message itself (422: a field the
// provider won't accept). It is deliberately NOT true of 401 and 403, even
// though they are 4xx: those mean the key is wrong, revoked or paused, or the
// from-domain isn't on the key yet — the operator's setup, not the email. The
// reason to put doevoe's queue in front of a provider is that mail survives
// exactly that kind of outage, so those stay queued and retry on the normal
// backoff schedule while the configuration gets fixed. 429 (over the
// workspace's rate) and 408 are transient by definition, as is every 5xx.
func (e *RelayError) Permanent() bool {
	switch e.Status {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusRequestTimeout, http.StatusTooManyRequests:
		return false
	}
	return e.Status >= 400 && e.Status < 500
}

// EmailEU delivers by handing the email to email.eu's sending API, which
// then signs it for the domain and delivers it from its own servers. doevoe
// builds no MIME and adds no DKIM signature on this path: the provider gets
// the fields and does both.
//
// "Sent" therefore means something narrower here than on the direct path:
// the provider accepted the message (202), not a recipient MX. A bounce after
// that point is recorded in the provider's log, not in doevoe's.
type EmailEU struct {
	Endpoint string
	Client   *http.Client
}

func NewEmailEU() *EmailEU {
	return &EmailEU{
		Endpoint: emailEUEndpoint,
		Client: &http.Client{
			Timeout: relayTimeout,
			// Never follow a redirect: the request carries the sending key
			// and the message, and neither should go anywhere but the
			// configured endpoint. A 3xx surfaces as a temporary RelayError.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

type euAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type euAttachment struct {
	Filename    string `json:"filename"`
	Content     string `json:"content"`
	ContentType string `json:"content_type,omitempty"`
	ContentID   string `json:"content_id,omitempty"`
}

type euMessage struct {
	From        euAddress         `json:"from"`
	To          euAddress         `json:"to"`
	ReplyTo     *euAddress        `json:"reply_to,omitempty"`
	Subject     string            `json:"subject"`
	Text        string            `json:"text,omitempty"`
	HTML        string            `json:"html,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Attachments []euAttachment    `json:"attachments,omitempty"`
}

// buildEUMessage maps a queued email onto the provider's NewMessage.
// Addresses go as {email, name} objects rather than "Name <addr>" strings so
// the display name crosses as plain UTF-8 and no second parser has to agree
// with net/mail about quoting.
func buildEUMessage(e *store.Email) (*euMessage, error) {
	// Same guard, for the same reason, as BuildMessage: an email that has
	// attachments must never go out without them just because a caller
	// skipped ListAttachments.
	if e.AttachmentCount > 0 && len(e.Attachments) == 0 {
		return nil, fmt.Errorf("email %d has %d attachment(s) but none were loaded", e.ID, e.AttachmentCount)
	}
	m := &euMessage{
		From:    euAddress{Email: e.From, Name: e.FromName},
		To:      euAddress{Email: e.To, Name: e.ToName},
		Subject: e.Subject,
		Text:    e.BodyText,
		HTML:    e.BodyHTML,
	}
	if e.ReplyTo != "" {
		// reply_to is stored as the caller wrote it ("Name <addr>" allowed),
		// already validated by send.Send with this same parser.
		a, err := mail.ParseAddress(e.ReplyTo)
		if err != nil {
			return nil, fmt.Errorf("reply_to: %w", err)
		}
		m.ReplyTo = &euAddress{Email: a.Address, Name: a.Name}
	}
	if e.HeadersJSON != "" && e.HeadersJSON != "{}" {
		if err := json.Unmarshal([]byte(e.HeadersJSON), &m.Headers); err != nil {
			return nil, fmt.Errorf("headers_json: %w", err)
		}
	}
	for _, a := range e.Attachments {
		ea := euAttachment{
			Filename:    a.Filename,
			Content:     base64.StdEncoding.EncodeToString(a.Content),
			ContentType: a.ContentType,
		}
		// The provider has no disposition field; a content_id is what marks
		// a part as inline (cid:) there. So it is passed for inline parts
		// only, which keeps an ordinary attachment a downloadable file.
		if a.Disposition == DispositionInline {
			ea.ContentID = a.ContentID
		}
		m.Attachments = append(m.Attachments, ea)
	}
	return m, nil
}

func (p *EmailEU) Send(ctx context.Context, e *store.Email, d *store.Domain) Result {
	start := time.Now()
	host := p.Endpoint
	if u, err := url.Parse(p.Endpoint); err == nil && u.Host != "" {
		host = u.Host
	}
	fail := func(err error) Result {
		res := Result{MXHost: host, Duration: time.Since(start), Err: err, Response: err.Error()}
		if re, ok := err.(*RelayError); ok {
			// The attempt log shows Code next to Response, so the response
			// carries the provider's own words without repeating the status.
			res.Code = re.Status
			if re.Message != "" {
				res.Response = strings.TrimPrefix(re.Code+": "+re.Message, ": ")
			}
		}
		return res
	}

	msg, err := buildEUMessage(e)
	if err != nil {
		return fail(err)
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return fail(err)
	}

	ctx, cancel := context.WithTimeout(ctx, relayTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fail(err)
	}
	req.Header.Set("Authorization", "Bearer "+d.ProviderAPIKey)
	req.Header.Set("Content-Type", "application/json")
	// The provider answers a repeated key+request with the first message's
	// id and sends nothing again. That closes the one window where doevoe
	// could double-send on this path: the provider accepted the message but
	// the response was lost (timeout, restart mid-request), so the attempt
	// is recorded as failed and retried. The key is the email id plus a
	// digest of the exact body, so it is stable across attempts of the same
	// email, but changes if an admin retry edits the recipient (a different
	// request under a reused key is not something to rely on) and can't
	// collide with another doevoe instance sharing the same sending key.
	sum := sha256.Sum256(body)
	req.Header.Set("Idempotency-Key", fmt.Sprintf("doevoe-%d-%s", e.ID, hex.EncodeToString(sum[:8])))

	resp, err := p.Client.Do(req)
	if err != nil {
		return fail(err) // network error or timeout: temporary
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRelayResponseBytes))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		re := &RelayError{Status: resp.StatusCode}
		var eb struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &eb) == nil {
			re.Code, re.Message = eb.Error.Code, eb.Error.Message
		}
		return fail(re)
	}

	var taken struct {
		ID       string `json:"id"`
		Repeated bool   `json:"repeated"`
	}
	json.Unmarshal(raw, &taken) // best effort: a 2xx is an acceptance either way
	response := "accepted by email.eu"
	if taken.ID != "" {
		response += ", id " + taken.ID
	}
	if taken.Repeated {
		response += " (already accepted on an earlier attempt)"
	}
	return Result{MXHost: host, Code: resp.StatusCode, Response: response, Duration: time.Since(start), TLS: true}
}
