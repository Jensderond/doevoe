// Command seed-demo populates a doevoe database with demo data for
// screenshots. Not part of the deployed binary; safe to delete.
package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/store"
	"doevoe/internal/webhook"
)

func main() {
	dir := os.Args[1]
	s, err := store.Open(filepath.Join(dir, "doevoe.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	priv1, _, _ := dkimkeys.Generate()
	client, err := s.CreateDomain("client.example", "mail1", priv1)
	if err != nil {
		log.Fatal(err)
	}
	s.SetDomainVerification(client.ID, true, true, true, "2026-07-21T06:00:00Z")
	priv2, _, _ := dkimkeys.Generate()
	shop, _ := s.CreateDomain("shop.example", "mail1", priv2)
	s.SetDomainVerification(shop.ID, true, true, false, "2026-07-21T06:00:00Z")

	_, hash, _ := store.GenerateAPIKey()
	kid, _ := s.CreateAPIKey("website contact form", client.ID, hash)
	s.TouchAPIKey(kid, "2026-07-20T18:12:00Z")
	_, hash2, _ := store.GenerateAPIKey()
	s.CreateAPIKey("webshop orders", shop.ID, hash2)

	// Two endpoints so the webhooks page shows both a healthy and a broken one.
	secret1, _ := store.GenerateWebhookSecret()
	if hook, err := s.CreateWebhook("app delivery log", "https://app.client.example/hooks/doevoe", secret1,
		0, []string{webhook.EventEmailSent, webhook.EventEmailFailed}); err == nil {
		s.TouchWebhook(hook.ID, 200, "", "2026-07-21T08:14:00Z")
		id, _ := s.EnqueueWebhookDelivery(&store.WebhookDelivery{
			WebhookID: hook.ID, EmailID: 1, Event: webhook.EventEmailSent,
			Payload:   `{"event":"email.sent","created_at":"2026-07-21T08:14:00Z","data":{"email":{"id":1,"status":"sent","domain":"client.example"}}}`,
			CreatedAt: "2026-07-21T08:14:00Z",
		})
		s.MarkWebhookDelivered(id, 200, "2026-07-21T08:14:01Z")
	}
	secret2, _ := store.GenerateWebhookSecret()
	if hook, err := s.CreateWebhook("ops slack bridge", "https://hooks.internal.example/doevoe", secret2,
		shop.ID, []string{webhook.EventDomainUnverified}); err == nil {
		s.TouchWebhook(hook.ID, 502, "HTTP 502: bad gateway", "2026-07-21T08:20:00Z")
		s.EnqueueWebhookDelivery(&store.WebhookDelivery{
			WebhookID: hook.ID, Event: webhook.EventDomainUnverified,
			Payload:   `{"event":"domain.unverified","created_at":"2026-07-21T08:20:00Z","data":{"domain":{"name":"shop.example","verified":false}}}`,
			CreatedAt: "2026-07-21T08:20:00Z",
		})
	}

	subjects := []string{
		"Welcome to client.example", "Your invoice #10", "Password reset",
		"Order confirmation", "Thanks for reaching out", "Your weekly digest",
	}
	names := []string{"anna", "bob", "carla", "daan", "emma", "floris", "gijs"}
	for i := 0; i < 58; i++ {
		day := 1 + i%20
		created := fmt.Sprintf("2026-07-%02dT%02d:%02d:00Z", day, 8+i%10, i%60)
		domainID := client.ID
		from := "hello@client.example"
		if i%5 == 0 {
			domainID = shop.ID
			from = "orders@shop.example"
		}
		id, err := s.EnqueueEmail(&store.Email{
			APIKeyID: kid, DomainID: domainID, From: from,
			To:      fmt.Sprintf("%s%d@gmail.com", names[i%len(names)], i),
			Subject: subjects[i%len(subjects)], BodyText: "Hi,\n\nThis is a demo email.\n",
			CreatedAt: created,
		})
		if err != nil {
			log.Fatal(err)
		}
		switch {
		case i%9 == 3:
			s.RecordAttempt(id, 1, 550, "gmail-smtp-in.l.google.com", "550-5.1.1 The email account does not exist", 412)
			s.MarkFailed(id, "550-5.1.1 The email account that you tried to reach does not exist")
		case i%13 == 5:
			s.RecordAttempt(id, 1, 421, "gmail-smtp-in.l.google.com", "421-4.7.0 Try again later", 380)
			s.MarkRetry(id, "2026-07-21T09:00:00Z", "421-4.7.0 IP not in allowed range, try again later")
		default:
			s.RecordAttempt(id, 1, 250, "gmail-smtp-in.l.google.com", "250 2.0.0 OK", 245)
			s.MarkSent(id, created[:11]+"12:00:00Z")
		}
	}
	fmt.Println("seeded", dir)
}
