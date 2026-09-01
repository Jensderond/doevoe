package store

import (
	"bytes"
	"testing"
)

func enqueueWithAttachments(t *testing.T, s *Store, domainID int64, atts []Attachment) int64 {
	t.Helper()
	id, err := s.EnqueueEmail(&Email{DomainID: domainID, From: "a@example.com", To: "u@dest.test",
		Subject: "hi", BodyText: "yo", Attachments: atts})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAttachmentsRoundTrip(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	// A payload with NULs and high-bit bytes: a TEXT column would mangle it,
	// which is why the column is a BLOB.
	binary := []byte{0x00, 0x01, 0xff, 0xfe, '\r', '\n', 0x00}
	id := enqueueWithAttachments(t, s, d.ID, []Attachment{
		{Filename: "invoice.pdf", ContentType: "application/pdf", Content: []byte("%PDF")},
		{Filename: "logo.png", ContentType: "image/png", Disposition: "inline", ContentID: "logo", Content: binary},
	})

	e, err := s.GetEmail(id)
	if err != nil {
		t.Fatal(err)
	}
	if e.AttachmentCount != 2 {
		t.Errorf("AttachmentCount = %d, want 2", e.AttachmentCount)
	}
	// The bytes must NOT come along with the row: every list query and every
	// ClaimDue selects emailCols, and BLOBs there would be carried everywhere.
	if e.Attachments != nil {
		t.Error("GetEmail loaded attachment bytes; it must not")
	}

	atts, err := s.ListAttachments(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 2 {
		t.Fatalf("got %d attachments, want 2", len(atts))
	}
	if atts[0].Filename != "invoice.pdf" || atts[1].Filename != "logo.png" {
		t.Errorf("insertion order not preserved: %q, %q", atts[0].Filename, atts[1].Filename)
	}
	if !bytes.Equal(atts[1].Content, binary) {
		t.Errorf("binary content = %v, want %v", atts[1].Content, binary)
	}
	if atts[1].Disposition != "inline" || atts[1].ContentID != "logo" {
		t.Errorf("inline metadata lost: %+v", atts[1])
	}
	// An empty disposition is normalized on write, so nothing downstream has to
	// treat "" and "attachment" as the same thing.
	if atts[0].Disposition != "attachment" {
		t.Errorf("disposition = %q, want attachment", atts[0].Disposition)
	}
	if atts[0].EmailID != id {
		t.Errorf("EmailID = %d, want %d", atts[0].EmailID, id)
	}
}

func TestListAttachmentMetaOmitsBytes(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	content := bytes.Repeat([]byte("x"), 4096)
	id := enqueueWithAttachments(t, s, d.ID, []Attachment{
		{Filename: "big.bin", ContentType: "application/octet-stream", Content: content},
	})
	metas, err := s.ListAttachmentMeta(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 {
		t.Fatalf("got %d metas, want 1", len(metas))
	}
	if metas[0].Size != int64(len(content)) {
		t.Errorf("Size = %d, want %d", metas[0].Size, len(content))
	}
	if metas[0].Filename != "big.bin" || metas[0].ContentType != "application/octet-stream" {
		t.Errorf("meta = %+v", metas[0])
	}
}

func TestEnqueueEmailWithoutAttachments(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id := enqueueTest(t, s, d.ID, "u@dest.test")
	e, _ := s.GetEmail(id)
	if e.AttachmentCount != 0 {
		t.Errorf("AttachmentCount = %d, want 0", e.AttachmentCount)
	}
	atts, err := s.ListAttachments(id)
	if err != nil || len(atts) != 0 {
		t.Fatalf("ListAttachments = %v, %v; want empty", atts, err)
	}
}

// TestEnqueueEmailFailureLeavesNothing: a failed enqueue must commit nothing.
// The property the transaction in EnqueueEmail exists for — that ClaimDue can
// never observe the email row before its attachment rows — is not observable
// from a single-threaded test (SetMaxOpenConns(1) serializes everything), so
// what is asserted here is the reachable half: an enqueue that fails writes no
// attachment rows and leaves earlier emails untouched.
func TestEnqueueEmailFailureLeavesNothing(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	first := enqueueWithAttachments(t, s, d.ID, []Attachment{
		{Filename: "a.txt", ContentType: "text/plain", Content: []byte("a")},
	})

	// A duplicate idempotency key fails the emails insert; the attachments in
	// the same call must not be left behind attached to nothing. The key needs
	// a real api_key_id: idx_emails_idem is on (api_key_id, idempotency_key),
	// and SQLite treats NULLs in a unique index as distinct, so an
	// admin-originated send (api_key_id NULL) never collides.
	_, hash, err := GenerateAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := s.CreateAPIKey("test", d.ID, hash)
	if err != nil {
		t.Fatal(err)
	}
	key := "dupe"
	if _, err := s.EnqueueEmail(&Email{APIKeyID: keyID, DomainID: d.ID, From: "a@example.com", To: "u@dest.test",
		Subject: "hi", BodyText: "yo", IdempotencyKey: key}); err != nil {
		t.Fatal(err)
	}
	_, err = s.EnqueueEmail(&Email{APIKeyID: keyID, DomainID: d.ID, From: "a@example.com", To: "u@dest.test",
		Subject: "hi", BodyText: "yo", IdempotencyKey: key,
		Attachments: []Attachment{{Filename: "orphan.txt", ContentType: "text/plain", Content: []byte("x")}}})
	if err == nil {
		t.Fatal("want a unique-constraint error for the duplicate idempotency key")
	}
	var orphans int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM email_attachments WHERE filename='orphan.txt'`).Scan(&orphans); err != nil {
		t.Fatal(err)
	}
	if orphans != 0 {
		t.Errorf("failed enqueue left %d orphaned attachment row(s)", orphans)
	}
	// The successful one is untouched.
	if atts, _ := s.ListAttachments(first); len(atts) != 1 {
		t.Errorf("first email now has %d attachments, want 1", len(atts))
	}
}

// TestRequeueKeepsAttachments: BuildMessage runs per attempt, so an admin retry
// hours (or a re-addressing) later must still find the bytes.
func TestRequeueKeepsAttachments(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id := enqueueWithAttachments(t, s, d.ID, []Attachment{
		{Filename: "invoice.pdf", ContentType: "application/pdf", Content: []byte("%PDF")},
	})
	s.ClaimDue(1, Now())
	if err := s.MarkFailed(id, "550 no such user"); err != nil {
		t.Fatal(err)
	}
	if err := s.RequeueEmail(id, "fixed@dest.test", "Fixed"); err != nil {
		t.Fatal(err)
	}
	e, _ := s.GetEmail(id)
	if e.AttachmentCount != 1 {
		t.Errorf("AttachmentCount = %d after requeue, want 1", e.AttachmentCount)
	}
	atts, _ := s.ListAttachments(id)
	if len(atts) != 1 || !bytes.Equal(atts[0].Content, []byte("%PDF")) {
		t.Errorf("attachment lost across requeue: %+v", atts)
	}
}

// TestClaimDueCarriesAttachmentCount: the count is what tells the worker to
// load the bytes at all, so it has to survive the claim.
func TestClaimDueCarriesAttachmentCount(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	enqueueWithAttachments(t, s, d.ID, []Attachment{
		{Filename: "a.txt", ContentType: "text/plain", Content: []byte("a")},
		{Filename: "b.txt", ContentType: "text/plain", Content: []byte("b")},
	})
	claimed, err := s.ClaimDue(10, Now())
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: %v %v", claimed, err)
	}
	if claimed[0].AttachmentCount != 2 {
		t.Errorf("claimed AttachmentCount = %d, want 2", claimed[0].AttachmentCount)
	}
	if claimed[0].Attachments != nil {
		t.Error("ClaimDue must not load attachment bytes")
	}
}

// TestEnqueueEmailNilAttachmentContent: a zero-byte attachment must store as
// zero bytes, not fail the content column's NOT NULL.
func TestEnqueueEmailNilAttachmentContent(t *testing.T) {
	s := testStore(t)
	d, _ := s.CreateDomain("example.com", "mail1", "PEM")
	id := enqueueWithAttachments(t, s, d.ID, []Attachment{
		{Filename: "empty.txt", ContentType: "text/plain", Content: nil},
	})
	atts, err := s.ListAttachments(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(atts) != 1 || len(atts[0].Content) != 0 {
		t.Fatalf("got %+v, want one zero-length attachment", atts)
	}
}
