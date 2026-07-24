// Package webhook delivers doevoe's own events to admin-configured HTTP
// endpoints: it snapshots a payload per subscribed endpoint into the store,
// then POSTs it (HMAC-signed) on its own ticker with its own retry schedule.
// Emitting is fail-open — a webhook problem must never affect the email
// operation that produced the event.
package webhook

import (
	"fmt"
	"net/url"
	"strings"
)

// Event names doevoe can deliver.
const (
	EventEmailSent        = "email.sent"
	EventEmailFailed      = "email.failed"
	EventDomainVerified   = "domain.verified"
	EventDomainUnverified = "domain.unverified"

	// EventTest is only ever produced by the admin UI's "send test event"
	// button, addressed at one endpoint. It is deliberately absent from
	// Events: nobody subscribes to it, so it can't be selected in the UI and
	// is never fanned out by Emit.
	EventTest = "webhook.test"
)

// Events is the subscribable catalogue, in the order the admin UI lists it.
var Events = []string{EventEmailSent, EventEmailFailed, EventDomainVerified, EventDomainUnverified}

// EventHelp is the one-line explanation the admin UI shows next to each event.
var EventHelp = map[string]string{
	EventEmailSent:        "An email was accepted by the recipient's MX server.",
	EventEmailFailed:      "An email failed permanently (5xx, or retries exhausted).",
	EventDomainVerified:   "A domain's SPF, DKIM and DMARC records all check out — sending is unblocked.",
	EventDomainUnverified: "A previously verified domain lost a DNS record — sending is blocked with 403.",
}

// ValidEvent reports whether name is a subscribable event.
func ValidEvent(name string) bool {
	for _, e := range Events {
		if e == name {
			return true
		}
	}
	return false
}

// ValidateURL checks a webhook target before it's stored, and again before
// every POST. Endpoints are admin-configured, so pointing one at a private
// address is allowed on purpose (self-hosted receivers on the same network
// are the common case); what's rejected is anything that isn't a plain
// absolute http/https URL, which could otherwise reach a non-HTTP transport.
func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("not a valid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("URL must start with http:// or https://")
	}
	if u.Host == "" {
		return fmt.Errorf("URL must include a host")
	}
	return nil
}

// NormalizeEvents keeps only known event names, de-duplicated and in the
// canonical Events order, and reports the first unknown name it saw.
func NormalizeEvents(in []string) (out []string, unknown string) {
	seen := map[string]bool{}
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !ValidEvent(e) {
			return nil, e
		}
		seen[e] = true
	}
	for _, e := range Events {
		if seen[e] {
			out = append(out, e)
		}
	}
	return out, ""
}
