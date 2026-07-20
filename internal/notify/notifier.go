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
}

func (n *Notifier) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now().UTC()
			for name, tick := range map[string]func(time.Time) error{
				"digest": n.DigestTick, "rate": n.RateTick, "stats": n.StatsTick,
			} {
				if err := tick(now); err != nil {
					slog.Error("notifier", "tick", name, "err", err)
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
	n.enqueue("doevoe: API key created",
		fmt.Sprintf("API key %q for domain %s was created.\n\n%s/admin/keys\n", name, domainName, n.BaseURL))
}

func (n *Notifier) KeyRevoked(name, domainName string) {
	n.enqueue("doevoe: API key revoked",
		fmt.Sprintf("API key %q for domain %s was revoked.\n\n%s/admin/keys\n", name, domainName, n.BaseURL))
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
	n.Store.SetState("digest_last_sent", store.FmtTime(now))
	return n.Store.ClearPendingFailures()
}

func (n *Notifier) RateTick(now time.Time) error {
	domains, err := n.Store.ListDomains()
	if err != nil {
		return err
	}
	since := store.FmtTime(now.Add(-time.Hour))
	for _, d := range domains {
		failed, total, err := n.Store.FailureRate(d.ID, since)
		if err != nil {
			return err
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
				return err
			}
			if sent {
				n.Store.SetState(stateKey, "fired")
			}
		case rate < n.Threshold && fired == "fired":
			n.Store.SetState(stateKey, "") // re-arm
		}
	}
	return nil
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
	prev := now.AddDate(0, -1, 0).Format("2006-01")
	stats, err := n.Store.MonthlyStats(prev)
	if err != nil {
		return err
	}
	reasons, _ := n.Store.TopFailureReasons(prev, 5)
	domains, _ := n.Store.ListDomains()

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
