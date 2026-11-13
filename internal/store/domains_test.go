package store

import "testing"

func TestDomainRoundTrip(t *testing.T) {
	s := testStore(t)
	d, err := s.CreateDomain("example.com", "mail1", "PEM")
	if err != nil {
		t.Fatal(err)
	}
	if d.Verified() {
		t.Fatal("new domain must be unverified")
	}
	if err := s.SetDomainVerification(d.ID, true, true, true, Now()); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDomainByName("example.com")
	if err != nil || got == nil || !got.Verified() {
		t.Fatalf("want verified domain, got %+v err %v", got, err)
	}
}

func TestDomainProviderGatesSending(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	if d.Provider != ProviderDirect || d.Relayed() || d.CanSend() {
		t.Fatalf("new domain must be direct and unable to send: %+v", d)
	}
	// Relayed without a key: still closed.
	s.SetDomainProvider(d.ID, ProviderEmailEU, "")
	if d, _ = s.GetDomain(d.ID); !d.Relayed() || d.CanSend() {
		t.Fatalf("relayed domain without a key must not send: %+v", d)
	}
	// Relayed with a key sends without doevoe's DNS being verified.
	s.SetDomainProvider(d.ID, ProviderEmailEU, "eu_0123456789abcdef")
	if d, _ = s.GetDomain(d.ID); !d.CanSend() || d.Verified() {
		t.Fatalf("relayed domain with a key must send, unverified: %+v", d)
	}
	if hint := d.ProviderKeyHint(); hint != "…cdef" {
		t.Fatalf("key hint = %q", hint)
	}
	// Back to direct: the verification gate applies again, the key is kept.
	s.SetDomainProvider(d.ID, ProviderDirect, d.ProviderAPIKey)
	if d, _ = s.GetDomain(d.ID); d.CanSend() || d.ProviderAPIKey == "" {
		t.Fatalf("direct unverified domain must not send, key kept: %+v", d)
	}
}
