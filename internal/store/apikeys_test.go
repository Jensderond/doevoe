package store

import "testing"

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
