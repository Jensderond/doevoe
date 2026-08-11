package mcpserver

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

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
		Name:        "get_email_status",
		Description: "Look up the delivery status of an email by id.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(false),
		},
	}, s.getEmailStatus)
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
