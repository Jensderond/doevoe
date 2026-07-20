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
	defer s.Close()

	notifier := &notify.Notifier{
		Store: s, AdminEmail: cfg.AdminEmail, SystemFrom: cfg.SystemFrom,
		BaseURL: "http://" + cfg.Hostname, Threshold: cfg.FailureRateThreshold, MinVolume: cfg.FailureRateMinVolume,
	}
	sender := delivery.NewSender(cfg.Hostname, cfg.SMTPPort)
	worker := &delivery.Worker{Store: s, Send: sender.Send, OnPermanentFailure: notifier.PermanentFailure}

	checkDomain := func(ctx context.Context, d *store.Domain) dnscheck.Result {
		pub, err := dkimkeys.PublicB64FromPrivatePEM(d.DKIMPrivateKey)
		if err != nil {
			slog.Error("dkim public key", "domain", d.Name, "err", err)
			return dnscheck.Result{}
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go worker.Run(ctx)
	go notifier.Run(ctx)
	go recheckDNSLoop(ctx, s, checkDomain) // hourly re-verification per spec

	srv := &http.Server{Addr: cfg.Listen, Handler: mux}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	slog.Info("doevoe listening", "addr", cfg.Listen, "hostname", cfg.Hostname)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("http", "err", err)
		os.Exit(1)
	}
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
				s.SetDomainVerification(d.ID, res.SPF.OK, res.DKIM.OK, res.DMARC.OK, store.Now())
			}
		}
	}
}
