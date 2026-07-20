package notify

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"doevoe/internal/store"
)

type Notifier struct {
	Store                           *store.Store
	AdminEmail, SystemFrom, BaseURL string
	Threshold                       float64
	MinVolume                       int
	// failureRateFn overrides Store.FailureRate in tests; nil means use the store.
	failureRateFn func(domainID int64, since string) (failed, total int, err error)
}

func (n *Notifier) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	ticks := []struct {
		name string
		fn   func(time.Time) error
	}{
		{"digest", n.DigestTick},
		{"rate", n.RateTick},
		{"stats", n.StatsTick},
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now().UTC()
			for _, tick := range ticks {
				if err := tick.fn(now); err != nil {
					slog.Error("notifier", "tick", tick.name, "err", err)
				}
			}
		}
	}
}

// enqueue sends a system notification through the normal queue.
// Returns false (without error) when the system domain is missing or unverified — fail-safe skip.
func (n *Notifier) enqueue(subject, body string) (bool, error) {
	domainName := n.SystemFrom[strings.LastIndex(n.SystemFrom, "@")+1:]
	d, err := n.Store.GetDomainByName(domainName)
	if err != nil {
		return false, err
	}
	if d == nil || !d.Verified() {
		slog.Warn("notification skipped: system domain not verified", "domain", domainName)
		return false, nil
	}
	_, err = n.Store.EnqueueEmail(&store.Email{
		DomainID: d.ID, From: n.SystemFrom, To: n.AdminEmail,
		Subject: subject, BodyText: body, IsSystem: true,
	})
	return err == nil, err
}

func (n *Notifier) PermanentFailure(emailID int64) {
	e, err := n.Store.GetEmail(emailID)
	if err != nil || e.IsSystem {
		return // loop guard: never notify about our own notifications
	}
	n.Store.AddPendingFailure(emailID)
}

func (n *Notifier) KeyCreated(name, domainName string) {
	if _, err := n.enqueue("doevoe: API key created",
		fmt.Sprintf("API key %q for domain %s was created.\n\n%s/admin/keys\n", name, domainName, n.BaseURL)); err != nil {
		slog.Error("notifier: key created notification failed", "key", name, "domain", domainName, "err", err)
	}
}

func (n *Notifier) KeyRevoked(name, domainName string) {
	if _, err := n.enqueue("doevoe: API key revoked",
		fmt.Sprintf("API key %q for domain %s was revoked.\n\n%s/admin/keys\n", name, domainName, n.BaseURL)); err != nil {
		slog.Error("notifier: key revoked notification failed", "key", name, "domain", domainName, "err", err)
	}
}

func (n *Notifier) DigestTick(now time.Time) error {
	pending, err := n.Store.ListPendingFailures()
	if err != nil || len(pending) == 0 {
		return err
	}
	last, _ := n.Store.GetState("digest_last_sent")
	if last != "" && now.Sub(store.ParseTime(last)) < time.Hour {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d email(s) permanently failed:\n\n", len(pending))
	for _, e := range pending {
		fmt.Fprintf(&b, "- To %s — %q\n  Error: %s\n  %s/admin/emails/%d\n\n", e.To, e.Subject, e.LastError, n.BaseURL, e.ID)
	}
	b.WriteString("Open the links to retry or fix the recipient address.\n")
	sent, err := n.enqueue(fmt.Sprintf("doevoe: %d failed email(s)", len(pending)), b.String())
	if err != nil || !sent {
		return err // keep pending for the next tick
	}
	// Clear pending first: if SetState below fails we only lose the cooldown
	// marker (harmless — the digest only sends when pending is non-empty),
	// rather than clearing state but leaving pending to be resent as a
	// duplicate-content digest.
	if err := n.Store.ClearPendingFailures(); err != nil {
		slog.Error("notifier: clearing pending failures failed", "err", err)
		return err
	}
	if err := n.Store.SetState("digest_last_sent", store.FmtTime(now)); err != nil {
		slog.Error("notifier: setting digest_last_sent state failed", "err", err)
		return err
	}
	return nil
}

func (n *Notifier) RateTick(now time.Time) error {
	domains, err := n.Store.ListDomains()
	if err != nil {
		return err
	}
	since := store.FmtTime(now.Add(-time.Hour))
	var firstErr error
	for _, d := range domains {
		var failed, total int
		var err error
		if n.failureRateFn != nil {
			failed, total, err = n.failureRateFn(d.ID, since)
		} else {
			failed, total, err = n.Store.FailureRate(d.ID, since)
		}
		if err != nil {
			slog.Error("notifier: failure rate lookup failed", "domain", d.Name, "err", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		stateKey := "rate_fired_" + d.Name
		fired, _ := n.Store.GetState(stateKey)
		rate := 0.0
		if total > 0 {
			rate = float64(failed) / float64(total)
		}
		switch {
		case total >= n.MinVolume && rate >= n.Threshold && fired != "fired":
			sent, err := n.enqueue("doevoe: elevated failure rate for "+d.Name,
				fmt.Sprintf("%.0f%% of the last %d delivery attempts for %s failed in the past hour.\nThis can indicate a blocklist or reputation problem.\n\n%s/admin/emails?domain=%d&status=failed\n",
					rate*100, total, d.Name, n.BaseURL, d.ID))
			if err != nil {
				slog.Error("notifier: enqueue rate alert failed", "domain", d.Name, "err", err)
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if sent {
				if err := n.Store.SetState(stateKey, "fired"); err != nil {
					slog.Error("notifier: setting rate_fired state failed", "domain", d.Name, "err", err)
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
			}
		case rate < n.Threshold && fired == "fired":
			if err := n.Store.SetState(stateKey, ""); err != nil { // re-arm
				slog.Error("notifier: re-arming rate_fired state failed", "domain", d.Name, "err", err)
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
		}
	}
	return firstErr
}

func (n *Notifier) StatsTick(now time.Time) error {
	current := now.Format("2006-01")
	last, _ := n.Store.GetState("last_stats_sent")
	if last == "" {
		return n.Store.SetState("last_stats_sent", current) // fresh install: no phantom report
	}
	if last == current {
		return nil
	}
	// Normalize to first-of-month before subtracting: AddDate on e.g. the 31st
	// can overflow into the current month again instead of landing in the
	// previous one (e.g. 2026-03-31 minus 1 month must be 2026-02, not 2026-03).
	firstOfMonth := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	prev := firstOfMonth.AddDate(0, -1, 0).Format("2006-01")
	stats, err := n.Store.MonthlyStats(prev)
	if err != nil {
		return err
	}
	reasons, err := n.Store.TopFailureReasons(prev, 5)
	if err != nil {
		slog.Warn("notifier: top failure reasons lookup failed", "month", prev, "err", err)
	}
	domains, err := n.Store.ListDomains()
	if err != nil {
		slog.Warn("notifier: list domains failed", "err", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "doevoe stats for %s\n\nPer domain:\n", prev)
	for _, st := range stats {
		total := st.Sent + st.Failed
		rate := 0.0
		if total > 0 {
			rate = float64(st.Sent) / float64(total) * 100
		}
		fmt.Fprintf(&b, "- %s: %d sent, %d failed (%.1f%% delivered)\n", st.DomainName, st.Sent, st.Failed, rate)
	}
	if len(stats) == 0 {
		b.WriteString("- no email activity\n")
	}
	if len(reasons) > 0 {
		b.WriteString("\nTop failure reasons:\n")
		for _, r := range reasons {
			fmt.Fprintf(&b, "- %dx %s\n", r.Count, r.Reason)
		}
	}
	b.WriteString("\nDNS verification status:\n")
	for _, d := range domains {
		state := "OK"
		if !d.Verified() {
			state = "NOT VERIFIED — sending blocked"
		}
		fmt.Fprintf(&b, "- %s: %s\n", d.Name, state)
	}
	sent, err := n.enqueue("doevoe: monthly stats "+prev, b.String())
	if err != nil || !sent {
		return err // retry next tick; state unchanged
	}
	return n.Store.SetState("last_stats_sent", current)
}
