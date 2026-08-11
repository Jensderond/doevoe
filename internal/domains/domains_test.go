package domains

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"doevoe/internal/dnscheck"
	"doevoe/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateNormalizesAndGeneratesKey(t *testing.T) {
	s := openStore(t)
	d, err := Create(s, "  Example.COM ")
	if err != nil {
		t.Fatal(err)
	}
	if d.Name != "example.com" || d.DKIMSelector != "mail1" || d.DKIMPrivateKey == "" {
		t.Fatalf("got %+v", d)
	}
}

func TestCreateRejectsInvalidName(t *testing.T) {
	s := openStore(t)
	for _, name := range []string{"", "a b.com", "a/b.com", "a@b.com"} {
		if _, err := Create(s, name); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("name %q: want ErrInvalidName, got %v", name, err)
		}
	}
}

func TestVerifyPersistsDeterminateResult(t *testing.T) {
	s := openStore(t)
	d, _ := Create(s, "example.com")
	check := func(context.Context, *store.Domain) dnscheck.Result {
		return dnscheck.Result{
			SPF:   dnscheck.RecordResult{OK: true},
			DKIM:  dnscheck.RecordResult{OK: true},
			DMARC: dnscheck.RecordResult{OK: true},
		}
	}
	res, persisted, err := Verify(context.Background(), s, check, d)
	if err != nil || !persisted || !res.AllOK() {
		t.Fatalf("res=%+v persisted=%v err=%v", res, persisted, err)
	}
	got, _ := s.GetDomain(d.ID)
	if !got.Verified() {
		t.Fatalf("domain not verified after persist: %+v", got)
	}
}

func TestVerifyNeverPersistsIndeterminate(t *testing.T) {
	s := openStore(t)
	d, _ := Create(s, "example.com")
	// Start verified: the whole point of the guard is that a transient
	// resolver blip must not flip a verified domain to unverified.
	s.SetDomainVerification(d.ID, true, true, true, store.Now())
	check := func(context.Context, *store.Domain) dnscheck.Result {
		return dnscheck.Result{Indeterminate: true}
	}
	_, persisted, err := Verify(context.Background(), s, check, d)
	if err != nil || persisted {
		t.Fatalf("persisted=%v err=%v", persisted, err)
	}
	got, _ := s.GetDomain(d.ID)
	if !got.Verified() {
		t.Fatal("indeterminate result flipped a verified domain")
	}
}
