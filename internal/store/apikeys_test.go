package store

import "testing"

func TestGetAPIKey(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	_, hash, _ := GenerateAPIKey()
	id, err := s.CreateAPIKey("k1", d.ID, hash)
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.GetAPIKey(id)
	if err != nil || k == nil || k.Name != "k1" || k.DomainID != d.ID {
		t.Fatalf("got %+v err=%v", k, err)
	}
	if missing, err := s.GetAPIKey(9999); err != nil || missing != nil {
		t.Fatalf("want nil,nil for missing id, got %+v err=%v", missing, err)
	}
	// Revoked keys must still be visible by id (revoke tooling needs them).
	s.RevokeAPIKey(id)
	k, err = s.GetAPIKey(id)
	if err != nil || k == nil || !k.Revoked {
		t.Fatalf("revoked key: got %+v err=%v", k, err)
	}
}

func TestAPIKeyLookupAndRevoke(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id, err := s.CreateAPIKey("site-a", d.ID, "abc123hash")
	if err != nil {
		t.Fatal(err)
	}
	k, err := s.GetAPIKeyByHash("abc123hash")
	if err != nil || k == nil || k.ID != id || k.DomainID != d.ID {
		t.Fatalf("lookup failed: %+v err %v", k, err)
	}
	if err := s.RevokeAPIKey(id); err != nil {
		t.Fatal(err)
	}
	if k, _ := s.GetAPIKeyByHash("abc123hash"); k != nil {
		t.Fatal("revoked key must not resolve")
	}
}
