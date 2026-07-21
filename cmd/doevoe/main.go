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
	"sync"
	"syscall"
	"time"

	"doevoe/internal/admin"
	"doevoe/internal/api"
	"doevoe/internal/config"
	"doevoe/internal/delivery"
	"doevoe/internal/dkimkeys"
	"doevoe/internal/dnscheck"
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

	adm := admin.New(s, cfg.AdminPassword, cfg.EgressIP, cfg.AdminEmail, cfg.Hostname)
	adm.CheckDomain = checkDomain
	adm.OnKeyCreated = notifier.KeyCreated
	adm.OnKeyRevoked = notifier.KeyRevoked

	mux := http.NewServeMux()
	(&api.Server{Store: s}).Routes(mux)
	adm.Routes(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup
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
			domains, err := s.ListDomains()
			if err != nil {
				continue
			}
			for _, d := range domains {
				res := check(ctx, d)
				if res.Indeterminate {
					// Transient resolver failure (or an unparsable DKIM key):
					// not a genuine re-check result, so don't let it flip an
					// already-verified domain to unverified and fail-close
					// its sends with 403 on a mere blip.
					slog.Warn("dns recheck indeterminate; not persisting", "domain", d.Name)
					continue
				}
				s.SetDomainVerification(d.ID, res.SPF.OK, res.DKIM.OK, res.DMARC.OK, store.Now())
			}
		}
	}
}
