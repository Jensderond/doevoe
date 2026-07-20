package dkimkeys

import (
	"strings"
	"testing"
)

func TestGenerateAndParseRoundTrip(t *testing.T) {
	priv, pub, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(priv, "RSA PRIVATE KEY") || pub == "" {
		t.Fatalf("bad keypair: %q %q", priv[:40], pub[:10])
	}
	key, err := ParsePrivateKey(priv)
	if err != nil || key.N.BitLen() != 2048 {
		t.Fatalf("parse: %v", err)
	}
}

func TestPublicKeyTXT(t *testing.T) {
	priv, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	txt, err := PublicKeyTXT(&key.PublicKey)
	if err != nil || !strings.HasPrefix(txt, "v=DKIM1; k=rsa; p=") {
		t.Fatalf("PublicKeyTXT: %v %q", err, txt)
	}
}

func TestPublicB64FromPrivatePEM(t *testing.T) {
	priv, _, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParsePrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	txt, err := PublicKeyTXT(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimPrefix(txt, "v=DKIM1; k=rsa; p=")

	got, err := PublicB64FromPrivatePEM(priv)
	if err != nil {
		t.Fatalf("PublicB64FromPrivatePEM: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if strings.HasPrefix(got, "v=DKIM1") {
		t.Fatalf("prefix not stripped: %q", got)
	}

	if _, err := PublicB64FromPrivatePEM("not a pem"); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestRecords(t *testing.T) {
	recs := Records("example.com", "mail1", "PUBKEY", "203.0.113.7", "ops@example.com")
	if len(recs) != 4 {
		t.Fatalf("want 4 records, got %d", len(recs))
	}
	spf, dkim, dmarc := recs[0], recs[1], recs[2]
	if spf.Host != "@" || spf.Value != "v=spf1 ip4:203.0.113.7 -all" {
		t.Errorf("spf: %+v", spf)
	}
	if dkim.Host != "mail1._domainkey" || dkim.Value != "v=DKIM1; k=rsa; p=PUBKEY" {
		t.Errorf("dkim: %+v", dkim)
	}
	if dmarc.Host != "_dmarc" || dmarc.Value != "v=DMARC1; p=quarantine; rua=mailto:ops@example.com" {
		t.Errorf("dmarc: %+v", dmarc)
	}
}
