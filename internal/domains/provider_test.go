package domains

import (
	"errors"
	"path/filepath"
	"testing"

	"doevoe/internal/store"
)

func TestSetProvider(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	d, _ := st.CreateDomain("example.com", "mail1", "PEM")
	reload := func() *store.Domain { d, _ := st.GetDomain(d.ID); return d }

	if err := SetProvider(st, d, "sendgrid", "k"); !errors.Is(err, ErrInvalidProvider) {
		t.Fatalf("unknown provider: %v", err)
	}
	if err := SetProvider(st, d, store.ProviderEmailEU, ""); !errors.Is(err, ErrProviderKey) {
		t.Fatalf("provider without key: %v", err)
	}
	// A key with a line break would split the Authorization header.
	if err := SetProvider(st, d, store.ProviderEmailEU, "eu_abc\r\nX-Evil: 1"); !errors.Is(err, ErrProviderKey) {
		t.Fatalf("key with CRLF: %v", err)
	}
	if got := reload(); got.Relayed() || got.ProviderAPIKey != "" {
		t.Fatalf("rejected changes must not persist: %+v", got)
	}

	if err := SetProvider(st, d, store.ProviderEmailEU, "  eu_secret  "); err != nil {
		t.Fatal(err)
	}
	d = reload()
	if !d.Relayed() || d.ProviderAPIKey != "eu_secret" {
		t.Fatalf("after set: %+v", d)
	}
	// Empty key keeps the stored one, in both directions.
	if err := SetProvider(st, d, store.ProviderDirect, ""); err != nil {
		t.Fatal(err)
	}
	if d = reload(); d.Relayed() || d.ProviderAPIKey != "eu_secret" {
		t.Fatalf("after switch to direct: %+v", d)
	}
	if err := SetProvider(st, d, store.ProviderEmailEU, ""); err != nil {
		t.Fatal(err)
	}
	if d = reload(); !d.Relayed() || d.ProviderAPIKey != "eu_secret" {
		t.Fatalf("after switch back: %+v", d)
	}
}
