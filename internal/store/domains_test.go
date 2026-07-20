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
