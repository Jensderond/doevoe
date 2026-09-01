package store

// Attachment is one MIME part carried by an email. Content holds the raw
// (already base64-decoded) bytes; the base64 encoding lives only in the wire
// format and in the built message, never in storage, so an attachment is
// re-encoded from the same bytes on every delivery attempt.
//
// Disposition is "attachment" or "inline". ContentID is the bare id without
// angle brackets (delivery/message.go adds them when writing the Content-ID
// header); an inline part is what an HTML body references as
// "cid:<ContentID>".
type Attachment struct {
	ID, EmailID            int64
	Filename, ContentType  string
	Disposition, ContentID string
	Content                []byte
}

const attachmentCols = `id, email_id, filename, content_type, disposition, content_id, content`

// ListAttachments returns an email's attachments in the order they were
// supplied (rowid order, which insertion in EnqueueEmail preserves). It reads
// the BLOBs, so only call it where the bytes are actually needed — the
// delivery worker, once per attempt. Use Email.AttachmentCount to merely
// detect that an email has attachments.
func (s *Store) ListAttachments(emailID int64) ([]Attachment, error) {
	rows, err := s.db.Query(`SELECT `+attachmentCols+` FROM email_attachments WHERE email_id=? ORDER BY id`, emailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Attachment
	for rows.Next() {
		var a Attachment
		if err := rows.Scan(&a.ID, &a.EmailID, &a.Filename, &a.ContentType, &a.Disposition, &a.ContentID, &a.Content); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AttachmentMeta is an attachment without its bytes: enough for the admin UI
// to list what is attached (and how big it is) without loading megabytes of
// BLOB into memory to render a page.
type AttachmentMeta struct {
	ID                     int64
	Filename, ContentType  string
	Disposition, ContentID string
	Size                   int64
}

func (s *Store) ListAttachmentMeta(emailID int64) ([]AttachmentMeta, error) {
	rows, err := s.db.Query(`SELECT id, filename, content_type, disposition, content_id, LENGTH(content)
		FROM email_attachments WHERE email_id=? ORDER BY id`, emailID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AttachmentMeta
	for rows.Next() {
		var a AttachmentMeta
		if err := rows.Scan(&a.ID, &a.Filename, &a.ContentType, &a.Disposition, &a.ContentID, &a.Size); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
