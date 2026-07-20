package delivery

import (
	"context"
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

func (w *Worker) Tick(ctx context.Context, now time.Time) error {
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
			rcptDomain := e.To[strings.LastIndex(e.To, "@")+1:]
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
	d, err := w.Store.GetDomain(e.DomainID)
	if err != nil {
		slog.Error("load domain", "email", e.ID, "err", err)
		w.Store.MarkRetry(e.ID, store.FmtTime(now.Add(time.Minute)), "internal: "+err.Error())
		return
	}
	res := w.Send(ctx, e, d)
	w.Store.RecordAttempt(e.ID, e.Attempts+1, res.Code, res.MXHost, res.Response, res.Duration.Milliseconds())

	if res.Err == nil {
		w.Store.MarkSent(e.ID, store.Now())
		return
	}
	errMsg := res.Err.Error()
	if Classify(res.Err) == ClassPerm {
		w.Store.MarkFailed(e.ID, errMsg)
		if w.OnPermanentFailure != nil {
			w.OnPermanentFailure(e.ID)
		}
		return
	}
	next, ok := NextAttempt(e.Attempts+1, now)
	if !ok {
		w.Store.MarkFailed(e.ID, "retries exhausted: "+errMsg)
		if w.OnPermanentFailure != nil {
			w.OnPermanentFailure(e.ID)
		}
		return
	}
	w.Store.MarkRetry(e.ID, store.FmtTime(next), errMsg)
}
