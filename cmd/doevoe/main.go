// Command doevoe is a self-hosted transactional email API: it exposes a
// JSON send/status API, an admin UI for domain/DKIM setup and API key
// management, and a background worker that delivers queued emails directly
// to recipient MX servers with retries and failure notifications.
package main

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"doevoe/internal/admin"
	"doevoe/internal/api"
	"doevoe/internal/config"
	"doevoe/internal/delivery"
	"doevoe/internal/dkimkeys"
	"doevoe/internal/dnsbl"
	"doevoe/internal/dnscheck"
	"doevoe/internal/domains"
	"doevoe/internal/inbound"
	"doevoe/internal/mcpserver"
	"doevoe/internal/notify"
	"doevoe/internal/store"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	s, err := store.Open(filepath.Join(cfg.DataDir, "doevoe.db"))
	if err != nil {
		slog.Error("store", "err", err)
		os.Exit(1)
	}

	baseURL := cfg.PublicURL
	if baseURL == "" {
		baseURL = "http://" + cfg.Hostname
	}
	notifier := &notify.Notifier{
		Store: s, AdminEmail: cfg.AdminEmail, SystemFrom: cfg.SystemFrom,
		BaseURL: baseURL, Threshold: cfg.FailureRateThreshold, MinVolume: cfg.FailureRateMinVolume,
	}
	sender := delivery.NewSender(cfg.Hostname, cfg.SMTPPort)
	worker := &delivery.Worker{Store: s, Send: sender.Send, OnPermanentFailure: notifier.PermanentFailure}

	checkDomain := func(ctx context.Context, d *store.Domain) dnscheck.Result {
		pub, err := dkimkeys.PublicB64FromPrivatePEM(d.DKIMPrivateKey)
		if err != nil {
			slog.Error("dkim public key", "domain", d.Name, "err", err)
			// Can't tell whether DNS is actually wrong without a valid key
			// to compare against; treat like any other indeterminate check
			// so callers don't persist a false "unverified".
			return dnscheck.Result{Indeterminate: true}
		}
		return dnscheck.Check(ctx, net.DefaultResolver, d.Name, d.DKIMSelector, pub, cfg.EgressIP)
	}

	// systemDomain/reportAddr: derived once from cfg.SystemFrom the same way
	// notify.Notifier derives its own domain part (domain of "user@domain"),
	// and shared by the admin UI's rendered DNS records and the inbound
	// receiver's accepted RCPT below, so both always agree.
	systemDomain := cfg.SystemFrom[strings.LastIndex(cfg.SystemFrom, "@")+1:]
	reportAddr := "dmarc@" + systemDomain

	adm := admin.New(s, cfg.AdminPassword, cfg.EgressIP, cfg.AdminEmail, cfg.Hostname)
	adm.CheckDomain = checkDomain
	adm.OnKeyCreated = notifier.KeyCreated
	adm.OnKeyRevoked = notifier.KeyRevoked
	adm.SystemDomain = systemDomain
	adm.DMARCRua = reportAddr

	mux := http.NewServeMux()
	(&api.Server{Store: s}).Routes(mux)
	adm.Routes(mux)
	if cfg.MCPToken != "" {
		m := &mcpserver.Server{
			Store: s, CheckDomain: checkDomain,
			EgressIP: cfg.EgressIP, DMARCRua: reportAddr,
			SystemDomain: systemDomain, Hostname: cfg.Hostname,
			OnKeyCreated: notifier.KeyCreated, OnKeyRevoked: notifier.KeyRevoked,
		}
		mux.Handle("/mcp", mcpserver.Handler(m, cfg.MCPToken))
		slog.Info("mcp endpoint enabled", "path", "/mcp")
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	// Bind the DMARC report receiver synchronously, before any background
	// goroutine starts: a bind failure here is a misconfiguration (the
	// operator asked for the receiver by not disabling it) and should exit
	// the process the same way a missing required env var does, rather than
	// surface later as a background error log.
	var inboundListener net.Listener
	if cfg.InboundListen != "" {
		var err error
		inboundListener, err = net.Listen("tcp", cfg.InboundListen)
		if err != nil {
			slog.Error("inbound listen", "addr", cfg.InboundListen, "err", err)
			os.Exit(1)
		}
	}

	var wg sync.WaitGroup
	if inboundListener != nil {
		inb := &inbound.Server{Store: s, ReportAddr: reportAddr, EgressIP: cfg.EgressIP,
			Hostname: cfg.Hostname, OnOwnFailure: notifier.DMARCFailure}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := inb.Serve(ctx, inboundListener); err != nil {
				slog.Error("inbound", "err", err)
			}
		}()
		slog.Info("dmarc report receiver listening", "addr", cfg.InboundListen, "rcpt", reportAddr)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		worker.Run(ctx)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		notifier.Run(ctx)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		recheckDNSLoop(ctx, s, checkDomain) // hourly re-verification per spec
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		hourlyMaintenanceLoop(ctx, s, notifier, cfg.EgressIP)
	}()

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: mux,
		// Bounds how long a slow/malicious client can hold a connection open
		// while trickling in request headers, so one such client can't tie
		// up a listener goroutine indefinitely.
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	slog.Info("doevoe listening", "addr", cfg.Listen, "hostname", cfg.Hostname)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("http", "err", err)
		stop()
		wg.Wait()
		s.Close()
		os.Exit(1)
	}

	// Server has stopped serving; make sure the background loops see
	// cancellation (already cancelled on the signal path) before we wait
	// for them and close the store, so nothing races store.Close.
	stop()
	wg.Wait()
	s.Close()
}

// recheckDNSLoop periodically re-verifies each domain's SPF/DKIM/DMARC
// records so that a domain that later loses (or gains) correct DNS records
// reflects that in the admin UI without requiring a manual "verify" click.
func recheckDNSLoop(ctx context.Context, s *store.Store, check func(context.Context, *store.Domain) dnscheck.Result) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			domainList, err := s.ListDomains()
			if err != nil {
				continue
			}
			for _, d := range domainList {
				// domains.Verify owns the indeterminate-result guard: a
				// transient resolver failure (or an unparsable DKIM key)
				// is never persisted, so it can't flip an already-verified
				// domain to unverified on a mere blip.
				domains.Verify(ctx, s, check, d)
			}
		}
	}
}

// hourlyMaintenanceLoop periodically checks the egress IP and every verified
// domain against the DNS blacklists in internal/dnsbl, persists determinate
// results, and notifies on listing transitions. Unverified domains are
// skipped: they can't send, so their listing status is noise. It also owns
// hourly DMARC report retention, pruning reports older than 90 days.
//
// Unlike recheckDNSLoop it runs once shortly after boot: there is no manual
// "check now" trigger for blacklists (domain verify covers DNS records), so
// without the initial run a fresh install would show nothing for an hour.
func hourlyMaintenanceLoop(ctx context.Context, s *store.Store, n *notify.Notifier, egressIP string) {
	run := func() {
		domains, err := s.ListDomains()
		if err != nil {
			slog.Error("blocklist: list domains", "err", err)
			return
		}
		var names []string
		for _, d := range domains {
			if d.Verified() {
				names = append(names, d.Name)
			}
		}
		// This budget is shared across all 3 + 2N lookups (egress IP zones
		// plus two zones per verified domain), run serially by dnsbl.Check —
		// revisit if the number of verified domains grows large enough that
		// 2 minutes stops being enough time for every lookup to complete.
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		statuses := dnsbl.Check(checkCtx, net.DefaultResolver, egressIP, names)
		cancel()
		for _, st := range statuses {
			if st.Verdict == dnsbl.Indeterminate {
				// Transient failure or a Spamhaus "public resolver" code:
				// not a genuine answer, so never persisted and never
				// alerted — same rule as the indeterminate DNS rechecks.
				slog.Warn("blocklist check indeterminate; not persisting",
					"target", st.Target, "zone", st.Zone, "response", st.Response)
				continue
			}
			transition, err := s.RecordBlocklistCheck(st.Target, st.Zone, st.Verdict == dnsbl.Listed, store.Now())
			if err != nil {
				slog.Error("blocklist: record check", "target", st.Target, "zone", st.Zone, "err", err)
				continue
			}
			switch transition {
			case "listed":
				slog.Warn("blocklist: newly listed", "target", st.Target, "zone", st.Zone, "response", st.Response)
				n.BlocklistHit(st.Target, st.Zone)
			case "cleared":
				slog.Info("blocklist: delisted", "target", st.Target, "zone", st.Zone)
				n.BlocklistCleared(st.Target, st.Zone)
			}
		}

		if pruned, err := s.PruneDMARCReports(store.FmtTime(time.Now().UTC().Add(-90 * 24 * time.Hour))); err != nil {
			slog.Error("dmarc prune", "err", err)
		} else if pruned > 0 {
			slog.Info("dmarc prune", "reports", pruned)
		}
	}

	select {
	case <-ctx.Done():
		return
	case <-time.After(time.Minute):
	}
	run()
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}
