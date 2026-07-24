package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"doevoe/internal/store"
)

// defaultTimeout bounds a single POST attempt end to end (dial, TLS,
// request, response). Kept short on purpose: a slow receiver must not hold a
// delivery slot, and the retry schedule exists precisely so a timeout is
// cheap. It is load-bearing against staleSendingWindow below.
const defaultTimeout = 10 * time.Second

// staleSendingWindow bounds how long a delivery may sit in 'sending' before
// it's put back on the queue, the same crash-recovery mechanism the email
// worker uses (see delivery.staleSendingWindow). It must comfortably exceed
// defaultTimeout — the hard cap on one attempt — so a merely slow POST isn't
// requeued and re-sent by the next tick while the first is still in flight,
// which would deliver the event twice.
const staleSendingWindow = 5 * time.Minute

// pruneInterval throttles the delivery-history prune to once an hour rather
// than once per (5s) tick; the DELETE is cheap but pointless at tick rate.
const pruneInterval = time.Hour

// defaultRetention is how long finished deliveries are kept for the admin UI.
const defaultRetention = 14 * 24 * time.Hour

// maxCapturedResponse caps how much of a receiver's response body is kept for
// the admin UI. Enough to show an error message, not enough for a hostile
// receiver to fill the database by replying with megabytes.
const maxCapturedResponse = 512

// Dispatcher fans events out to subscribed webhooks and delivers the queued
// payloads on its own ticker.
type Dispatcher struct {
	Store *store.Store
	// Client overrides the HTTP client used for deliveries (tests inject one).
	Client *http.Client
	// Interval, BatchSize and Retention default to 5s, 20 and 14 days.
	Interval  time.Duration
	BatchSize int
	Retention time.Duration

	once          sync.Once
	defaultClient *http.Client
	lastPrune     time.Time
}

// envelope is the JSON body POSTed to receivers. Data is event-specific:
// {"email": {...}} for email.*, {"domain": {...}} for domain.*.
type envelope struct {
	Event     string `json:"event"`
	CreatedAt string `json:"created_at"`
	Data      any    `json:"data"`
}

type emailData struct {
	ID        int64  `json:"id"`
	Status    string `json:"status"`
	Domain    string `json:"domain"`
	From      string `json:"from"`
	To        string `json:"to"`
	Subject   string `json:"subject"`
	Attempts  int    `json:"attempts"`
	LastError string `json:"last_error,omitempty"`
	CreatedAt string `json:"created_at"`
	SentAt    string `json:"sent_at,omitempty"`
	// System marks doevoe's own notification mail (failure digests, monthly
	// stats). Those go through the same queue as API traffic, so they produce
	// the same events; the flag is here so a consumer can filter out mail it
	// never asked doevoe to send. Absent for ordinary emails.
	System bool `json:"system,omitempty"`
}

type domainData struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	Verified      bool   `json:"verified"`
	SPFVerified   bool   `json:"spf_verified"`
	DKIMVerified  bool   `json:"dkim_verified"`
	DMARCVerified bool   `json:"dmarc_verified"`
	LastCheckedAt string `json:"last_checked_at,omitempty"`
}

// EmailEvent emits an email.* event for the given email. Safe to call from
// the delivery worker: it never returns an error and never blocks on the
// network — the actual POST happens on the dispatcher's own ticker.
func (d *Dispatcher) EmailEvent(event string, emailID int64) {
	hooks, err := d.subscribers(event)
	if err != nil || len(hooks) == 0 {
		return
	}
	e, err := d.Store.GetEmail(emailID)
	if err != nil {
		slog.Error("webhook: load email for event", "event", event, "email", emailID, "err", err)
		return
	}
	data := emailData{
		ID: e.ID, Status: e.Status, From: e.From, To: e.To, Subject: e.Subject,
		Attempts: e.Attempts, LastError: e.LastError, CreatedAt: e.CreatedAt, SentAt: e.SentAt,
		System: e.IsSystem,
	}
	// A missing domain row only costs the payload its domain name; the event
	// itself is still worth delivering.
	if dom, err := d.Store.GetDomain(e.DomainID); err == nil {
		data.Domain = dom.Name
	}
	d.fanOut(hooks, event, e.ID, map[string]any{"email": data})
}

// DomainEvent emits a domain.* event for the given domain.
func (d *Dispatcher) DomainEvent(event string, domainID int64) {
	hooks, err := d.subscribers(event)
	if err != nil || len(hooks) == 0 {
		return
	}
	dom, err := d.Store.GetDomain(domainID)
	if err != nil {
		slog.Error("webhook: load domain for event", "event", event, "domain", domainID, "err", err)
		return
	}
	d.fanOut(hooks, event, 0, map[string]any{"domain": domainData{
		ID: dom.ID, Name: dom.Name, Verified: dom.Verified(),
		SPFVerified: dom.SPFVerified, DKIMVerified: dom.DKIMVerified, DMARCVerified: dom.DMARCVerified,
		LastCheckedAt: dom.LastCheckedAt,
	}})
}

// Test queues a webhook.test delivery for one endpoint so the admin can
// confirm the receiver's URL and signature check work. Unlike the event
// emitters this reports failure, so the admin UI can say the endpoint is gone
// instead of silently doing nothing.
func (d *Dispatcher) Test(webhookID int64) error {
	w, err := d.Store.GetWebhook(webhookID)
	if err != nil {
		return err
	}
	payload, err := marshalEnvelope(EventTest, map[string]any{
		"webhook": map[string]any{"id": w.ID, "name": w.Name},
	})
	if err != nil {
		return err
	}
	_, err = d.Store.EnqueueWebhookDelivery(&store.WebhookDelivery{
		WebhookID: w.ID, Event: EventTest, Payload: payload,
	})
	return err
}

// subscribers looks up the active endpoints for an event. Errors are logged
// and reported as "none", so an event emit is always fail-open.
func (d *Dispatcher) subscribers(event string) ([]*store.Webhook, error) {
	hooks, err := d.Store.ListActiveWebhooksForEvent(event)
	if err != nil {
		slog.Error("webhook: list subscribers", "event", event, "err", err)
		return nil, err
	}
	return hooks, nil
}

// fanOut snapshots the payload once and queues one delivery row per endpoint.
// The snapshot is what makes a retry hours later replay the state as of the
// event rather than as of the retry.
func (d *Dispatcher) fanOut(hooks []*store.Webhook, event string, emailID int64, data any) {
	payload, err := marshalEnvelope(event, data)
	if err != nil {
		slog.Error("webhook: marshal payload", "event", event, "err", err)
		return
	}
	for _, w := range hooks {
		if _, err := d.Store.EnqueueWebhookDelivery(&store.WebhookDelivery{
			WebhookID: w.ID, EmailID: emailID, Event: event, Payload: payload,
		}); err != nil {
			slog.Error("webhook: enqueue delivery", "event", event, "webhook", w.ID, "err", err)
		}
	}
}

func marshalEnvelope(event string, data any) (string, error) {
	buf, err := json.Marshal(envelope{Event: event, CreatedAt: store.Now(), Data: data})
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func (d *Dispatcher) Run(ctx context.Context) {
	interval := d.Interval
	if interval == 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := d.Tick(ctx, time.Now()); err != nil {
				slog.Error("webhook tick", "err", err)
			}
		}
	}
}

func (d *Dispatcher) Tick(ctx context.Context, now time.Time) error {
	staleCutoff := store.FmtTime(now.Add(-staleSendingWindow))
	if n, err := d.Store.RequeueStaleWebhookDeliveries(staleCutoff); err != nil {
		slog.Error("webhook: requeue stale deliveries", "err", err)
	} else if n > 0 {
		slog.Warn("webhook: requeued stale deliveries", "count", n)
	}
	d.maybePrune(now)

	batch := d.BatchSize
	if batch == 0 {
		batch = 20
	}
	deliveries, err := d.Store.ClaimDueWebhookDeliveries(batch, store.FmtTime(now))
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	for _, del := range deliveries {
		wg.Add(1)
		go func(del *store.WebhookDelivery) {
			defer wg.Done()
			d.process(ctx, del, now)
		}(del)
	}
	wg.Wait()
	return nil
}

func (d *Dispatcher) maybePrune(now time.Time) {
	retention := d.Retention
	if retention == 0 {
		retention = defaultRetention
	}
	if retention < 0 || now.Sub(d.lastPrune) < pruneInterval {
		return
	}
	d.lastPrune = now
	if n, err := d.Store.PruneWebhookDeliveries(store.FmtTime(now.Add(-retention))); err != nil {
		slog.Error("webhook: prune deliveries", "err", err)
	} else if n > 0 {
		slog.Info("webhook: pruned delivery history", "count", n)
	}
}

// process delivers one claimed row and records the outcome. A panic anywhere
// below must not take down the tick or strand the row in 'sending', so it's
// treated like any other temporary failure.
func (d *Dispatcher) process(ctx context.Context, del *store.WebhookDelivery, now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("webhook: panic delivering", "delivery", del.ID, "panic", r)
			d.retryOrFail(del, now, 0, fmt.Sprintf("panic: %v", r))
		}
	}()

	w, err := d.Store.GetWebhook(del.WebhookID)
	if err != nil {
		if store.IsNotFound(err) {
			// Endpoint deleted while this row was in flight: nothing to
			// deliver to, and retrying can never succeed.
			d.Store.MarkWebhookDeliveryFailed(del.ID, 0, "webhook endpoint was deleted")
			return
		}
		slog.Error("webhook: load endpoint", "delivery", del.ID, "webhook", del.WebhookID, "err", err)
		d.retryOrFail(del, now, 0, err.Error())
		return
	}

	code, err := d.post(ctx, w, del)
	errMsg := ""
	if err != nil {
		errMsg = truncate(err.Error(), maxCapturedResponse)
	}
	if terr := d.Store.TouchWebhook(w.ID, code, errMsg, store.Now()); terr != nil {
		slog.Error("webhook: touch endpoint", "webhook", w.ID, "err", terr)
	}
	switch {
	case err == nil:
		if err := d.Store.MarkWebhookDelivered(del.ID, code, store.Now()); err != nil {
			slog.Error("webhook: mark delivered", "delivery", del.ID, "err", err)
		}
	case permanent(code):
		if err := d.Store.MarkWebhookDeliveryFailed(del.ID, code, errMsg); err != nil {
			slog.Error("webhook: mark failed", "delivery", del.ID, "err", err)
		}
	default:
		d.retryOrFail(del, now, code, errMsg)
	}
}

func (d *Dispatcher) retryOrFail(del *store.WebhookDelivery, now time.Time, code int, errMsg string) {
	next, ok := NextAttempt(del.Attempts+1, now)
	if !ok {
		if err := d.Store.MarkWebhookDeliveryFailed(del.ID, code, "retries exhausted: "+errMsg); err != nil {
			slog.Error("webhook: mark failed", "delivery", del.ID, "err", err)
		}
		return
	}
	if err := d.Store.MarkWebhookDeliveryRetry(del.ID, store.FmtTime(next), code, errMsg); err != nil {
		slog.Error("webhook: mark retry", "delivery", del.ID, "err", err)
	}
}

// permanent reports whether an HTTP status means retrying can never help.
// Only 410 Gone qualifies: it's the documented way for a receiver to say
// "stop sending me this". Every other status — including 404 and 401, which
// are routinely a receiver that hasn't finished deploying its handler — is
// retried.
func permanent(code int) bool { return code == http.StatusGone }

// post makes one attempt. A returned error means the attempt failed; code is
// the HTTP status when there was one, 0 when the request never completed.
func (d *Dispatcher) post(ctx context.Context, w *store.Webhook, del *store.WebhookDelivery) (int, error) {
	// Re-check the URL: it was validated on the way in, but a row edited
	// outside the admin UI (or by a future code path) must not turn into a
	// request to a non-HTTP transport.
	if err := ValidateURL(w.URL); err != nil {
		return 0, err
	}
	body := []byte(del.Payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, strings.NewReader(del.Payload))
	if err != nil {
		return 0, err
	}
	// The timestamp is per attempt, not per event: receivers reject
	// signatures outside a freshness window, and a retried delivery is a
	// legitimately fresh request carrying an old payload.
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "doevoe-webhooks/1")
	req.Header.Set("X-Doevoe-Event", del.Event)
	req.Header.Set("X-Doevoe-Delivery", strconv.FormatInt(del.ID, 10))
	req.Header.Set("X-Doevoe-Attempt", strconv.Itoa(del.Attempts+1))
	req.Header.Set("X-Doevoe-Timestamp", ts)
	req.Header.Set("X-Doevoe-Signature", Sign(w.Secret, ts, body))

	resp, err := d.client().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	// Read a bounded prefix of the body: it's what the admin UI shows for a
	// failed delivery, and draining lets the connection be reused.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxCapturedResponse))
	if resp.StatusCode/100 == 2 {
		return resp.StatusCode, nil
	}
	if snippet := strings.TrimSpace(string(respBody)); snippet != "" {
		return resp.StatusCode, fmt.Errorf("HTTP %d: %s", resp.StatusCode, snippet)
	}
	return resp.StatusCode, fmt.Errorf("HTTP %d", resp.StatusCode)
}

func (d *Dispatcher) client() *http.Client {
	if d.Client != nil {
		return d.Client
	}
	d.once.Do(func() {
		d.defaultClient = &http.Client{
			Timeout: defaultTimeout,
			// Don't follow redirects: Go drops the body (and our signed
			// payload) on a 301/302 replay as GET, and following one would
			// hand a signed request to a host the admin never configured.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("redirects are not followed; configure the final URL")
			},
		}
	})
	return d.defaultClient
}

// Sign returns the X-Doevoe-Signature header value for a delivery: an
// HMAC-SHA256 over "<timestamp>.<raw body>", keyed with the endpoint's
// secret. Signing the timestamp along with the body is what lets a receiver
// reject replays of an old, otherwise-valid request.
func Sign(secret, timestamp string, body []byte) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(timestamp))
	m.Write([]byte("."))
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
