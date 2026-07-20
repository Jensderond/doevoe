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
