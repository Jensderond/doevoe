package mcpserver

import (
	"context"
	"fmt"
	"net/mail"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"doevoe/internal/send"
)

type sendEmailInput struct {
	From           string            `json:"from" jsonschema:"sender address on a domain registered and verified in doevoe; display-name form \"Name <addr@domain>\" is preserved"`
	To             string            `json:"to" jsonschema:"recipient address"`
	Subject        string            `json:"subject"`
	HTML           string            `json:"html,omitempty" jsonschema:"HTML body; provide html and/or text"`
	Text           string            `json:"text,omitempty" jsonschema:"plain-text body; provide html and/or text"`
	ReplyTo        string            `json:"reply_to,omitempty"`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"extra headers; From/To/Subject/Date/Message-ID and other doevoe-set headers are rejected"`
	Attachments    []attachmentInput `json:"attachments,omitempty" jsonschema:"files to attach; each carries its bytes base64-encoded"`
	IdempotencyKey string            `json:"idempotency_key,omitempty" jsonschema:"dedupe key: repeating a call with the same key replays the original result instead of sending twice"`
}

type attachmentInput struct {
	Filename    string `json:"filename" jsonschema:"file name shown to the recipient; must not contain a path separator"`
	Content     string `json:"content" jsonschema:"the file's bytes, base64-encoded"`
	ContentType string `json:"content_type,omitempty" jsonschema:"MIME type; guessed from the filename extension when omitted"`
	Disposition string `json:"disposition,omitempty" jsonschema:"\"attachment\" (default) or \"inline\" for an image the HTML body references as cid:<content_id>"`
	ContentID   string `json:"content_id,omitempty" jsonschema:"id an inline part is referenced by, without angle brackets; e.g. content_id \"logo\" is used as <img src=\"cid:logo\">"`
}

type sendEmailOutput struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
	Replay bool   `json:"replay,omitempty" jsonschema:"true when this was an idempotent replay of an earlier send"`
}

type emailStatusInput struct {
	ID int64 `json:"id" jsonschema:"the email id returned by send_email"`
}

type emailStatusOutput struct {
	ID        int64  `json:"id"`
	Status    string `json:"status"`
	Attempts  int    `json:"attempts"`
	LastError string `json:"last_error,omitempty"`
	CreatedAt string `json:"created_at"`
	SentAt    string `json:"sent_at,omitempty"`
}

func (s *Server) addEmailTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "send_email",
		Description: "Queue a real transactional email for delivery. The from-address domain must already be registered and DNS-verified in doevoe. This immediately queues a real email to a real recipient.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: boolPtr(false), // additive: queues a row, overwrites nothing
			IdempotentHint:  false,
			OpenWorldHint:   boolPtr(true), // delivers to arbitrary external mailboxes
		},
	}, s.sendEmail)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_email_status",
		Description: "Look up the delivery status of an email by id.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(false),
		},
	}, s.getEmailStatus)
}

func (s *Server) sendEmail(ctx context.Context, req *mcp.CallToolRequest, in sendEmailInput) (*mcp.CallToolResult, sendEmailOutput, error) {
	// MCP is admin-scoped rather than key-scoped, so the sending domain is
	// derived from the from address instead of an API key. send.Send
	// re-validates the from/domain match and the verified requirement.
	addr, err := mail.ParseAddress(in.From)
	if err != nil {
		return nil, sendEmailOutput{}, fmt.Errorf("invalid from address")
	}
	name := addr.Address[strings.LastIndex(addr.Address, "@")+1:]
	d, err := s.Store.GetDomainByName(strings.ToLower(name))
	if err != nil {
		return nil, sendEmailOutput{}, err
	}
	if d == nil {
		return nil, sendEmailOutput{}, fmt.Errorf("domain %s is not registered in doevoe; create it with create_domain first", name)
	}
	attachments := make([]send.Attachment, len(in.Attachments))
	for i, a := range in.Attachments {
		attachments[i] = send.Attachment{
			Filename: a.Filename, ContentType: a.ContentType, ContentBase64: a.Content,
			Disposition: a.Disposition, ContentID: a.ContentID,
		}
	}
	res, serr := send.Send(s.Store, 0, d.ID, send.Input{
		From: in.From, To: in.To, Subject: in.Subject, HTML: in.HTML, Text: in.Text,
		ReplyTo: in.ReplyTo, Headers: in.Headers, Attachments: attachments,
		IdempotencyKey: in.IdempotencyKey,
	})
	if serr != nil {
		return nil, sendEmailOutput{}, serr
	}
	return nil, sendEmailOutput{ID: res.ID, Status: res.Status, Replay: res.Replay}, nil
}

func (s *Server) getEmailStatus(ctx context.Context, req *mcp.CallToolRequest, in emailStatusInput) (*mcp.CallToolResult, emailStatusOutput, error) {
	e, err := s.Store.GetEmail(in.ID)
	if err != nil {
		return nil, emailStatusOutput{}, fmt.Errorf("email %d not found", in.ID)
	}
	return nil, emailStatusOutput{
		ID: e.ID, Status: e.Status, Attempts: e.Attempts,
		LastError: e.LastError, CreatedAt: e.CreatedAt, SentAt: e.SentAt,
	}, nil
}
