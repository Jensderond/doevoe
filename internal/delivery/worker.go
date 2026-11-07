package delivery

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"doevoe/internal/store"
)

type SendFunc func(ctx context.Context, e *store.Email, d *store.Domain) Result

type Worker struct {
	Store              *store.Store
	Send               SendFunc
	Interval           time.Duration
	BatchSize          int
	PerDomainLimit     int
	OnPermanentFailure func(emailID int64)
}

func (w *Worker) Run(ctx context.Context) {
	interval := w.Interval
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
			if err := w.Tick(ctx, time.Now()); err != nil {
				slog.Error("worker tick", "err", err)
			}
		}
	}
}

// staleSendingWindow bounds how long an email may sit in 'sending' before
// RequeueStaleSending puts it back on the queue for another worker tick to
// pick up. It must comfortably exceed the sender's worst-case time to give
// up on a single Send. That worst case is now a hard, socket-level cap:
// Sender.OverallTimeout (30m by default, see NewSender/defaultOverallTimeout
// in sender.go) wraps the entire Send call in a context deadline that is set
// on every dialed conn immediately after dial, bounding ALL I/O on that
// conn - including the pre-TLS greet+EHLO+STARTTLS exchange (sender.go's
// startTLS) and the TLS handshake, which happen before any *smtp.Client and
// its commandTimeout/submissionTimeout exist. commandTimeout/submissionTimeout
// remain in effect as an inner bound within that 30m envelope. 45m leaves
// 15m of headroom above the 30m hard cap so a send that is merely slow
// (e.g. a tarpitting MX) doesn't get requeued and re-sent by a second worker
// while the first is still in flight, which would double-deliver the email.
// See internal/delivery/sender.go for the timeout/attempt-cap constants this
// is derived from.
const staleSendingWindow = 45 * time.Minute

func (w *Worker) Tick(ctx context.Context, now time.Time) error {
	staleCutoff := store.FmtTime(now.Add(-staleSendingWindow))
	if n, err := w.Store.RequeueStaleSending(staleCutoff); err != nil {
		slog.Error("requeue stale sending", "err", err)
	} else if n > 0 {
		slog.Warn("requeued stale sending emails", "count", n)
	}

	batch := w.BatchSize
	if batch == 0 {
		batch = 10
	}
	emails, err := w.Store.ClaimDue(batch, store.FmtTime(now))
	if err != nil {
		return err
	}
	limit := w.PerDomainLimit
	if limit == 0 {
		limit = 2
	}
	sems := map[string]chan struct{}{}
	var mu sync.Mutex
	sem := func(domain string) chan struct{} {
		mu.Lock()
		defer mu.Unlock()
		if sems[domain] == nil {
			sems[domain] = make(chan struct{}, limit)
		}
		return sems[domain]
	}

	var wg sync.WaitGroup
	for _, e := range emails {
		wg.Add(1)
		go func(e *store.Email) {
			defer wg.Done()
			rcptDomain := strings.ToLower(e.To[strings.LastIndex(e.To, "@")+1:])
			s := sem(rcptDomain)
			s <- struct{}{}
			defer func() { <-s }()
			w.process(ctx, e, now)
		}(e)
	}
	wg.Wait()
	return nil
}

func (w *Worker) process(ctx context.Context, e *store.Email, now time.Time) {
	// A panic in Send (or anywhere below) must not take down the whole tick, and
	// must not strand the email in 'sending'. Treat it like any other temporary
	// send error: record the attempt and reschedule/exhaust on the normal schedule.
	defer func() {
		if r := recover(); r != nil {
			errMsg := fmt.Sprintf("panic: %v", r)
			slog.Error("panic processing email", "email", e.ID, "panic", r)
			w.recordAttempt(e, 0, "", errMsg, 0)
			w.retryOrFail(e, now, errMsg)
		}
	}()

	d, err := w.Store.GetDomain(e.DomainID)
	if err != nil {
		slog.Error("load domain", "email", e.ID, "err", err)
		w.recordAttempt(e, 0, "", err.Error(), 0)
		w.retryOrFail(e, now, err.Error())
		return
	}
	// Attachment bytes are deliberately not part of the claimed row (they would
	// ride along on every ClaimDue and every admin list query — see
	// store.Email.Attachments); load them here, per attempt, right before the
	// send. Reading them fresh each attempt is also what makes a retry hours
	// later still have the data: nothing is held in memory between attempts,
	// the rows outlive the process, and RequeueEmail leaves them attached. A
	// load failure is treated like any other temporary error rather than
	// sending a message with its attachments missing (BuildMessage refuses that
	// too, from AttachmentCount).
	if e.AttachmentCount > 0 {
		atts, err := w.Store.ListAttachments(e.ID)
		if err != nil {
			slog.Error("load attachments", "email", e.ID, "err", err)
			w.recordAttempt(e, 0, "", err.Error(), 0)
			w.retryOrFail(e, now, err.Error())
			return
		}
		e.Attachments = atts
	}
	res := w.Send(ctx, e, d)
	w.recordAttempt(e, res.Code, res.MXHost, res.Response, res.Duration.Milliseconds())

	if res.Err == nil {
		if err := w.Store.MarkSent(e.ID, store.Now()); err != nil {
			slog.Error("mark sent", "email", e.ID, "err", err)
		}
		return
	}
	errMsg := res.Err.Error()
	if Classify(res.Err) == ClassPerm {
		w.markFailed(e, errMsg)
		return
	}
	w.retryOrFail(e, now, errMsg)
}

func (w *Worker) recordAttempt(e *store.Email, code int, mxHost, response string, durationMs int64) {
	if err := w.Store.RecordAttempt(e.ID, e.Attempts+1, code, mxHost, response, durationMs); err != nil {
		slog.Error("record attempt", "email", e.ID, "err", err)
	}
}

func (w *Worker) markFailed(e *store.Email, errMsg string) {
	if err := w.Store.MarkFailed(e.ID, errMsg); err != nil {
		slog.Error("mark failed", "email", e.ID, "err", err)
	}
	if w.OnPermanentFailure != nil {
		w.OnPermanentFailure(e.ID)
	}
}

// retryOrFail applies the standard temporary-error handling shared by send
// failures, domain-load failures, and recovered panics: reschedule on the
// backoff schedule, or mark permanently failed once it's exhausted.
func (w *Worker) retryOrFail(e *store.Email, now time.Time, errMsg string) {
	next, ok := NextAttempt(e.Attempts+1, now)
	if !ok {
		w.markFailed(e, "retries exhausted: "+errMsg)
		return
	}
	if err := w.Store.MarkRetry(e.ID, store.FmtTime(next), errMsg); err != nil {
		slog.Error("mark retry", "email", e.ID, "err", err)
	}
}
