package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"doevoe/internal/store"
)

type createKeyInput struct {
	Name   string `json:"name" jsonschema:"a label for the key, e.g. the app that will use it"`
	Domain string `json:"domain" jsonschema:"the registered domain this key may send from"`
}

type createKeyOutput struct {
	ID    int64  `json:"id"`
	Token string `json:"token" jsonschema:"the bearer token for the API; it is shown only this once and stored hashed, so save it now"`
}

type revokeKeyInput struct {
	ID int64 `json:"id" jsonschema:"the api key id to revoke"`
}

type revokeKeyOutput struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	Revoked bool   `json:"revoked"`
}

func (s *Server) addKeyTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_api_key",
		Description: "Create an API key scoped to one sending domain. The returned token is a live sending credential shown exactly once.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: boolPtr(false),
			IdempotentHint:  false,
			OpenWorldHint:   boolPtr(false),
		},
	}, s.createAPIKey)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "revoke_api_key",
		Description: "Revoke an API key by id. Requests using the key stop authenticating immediately; this cannot be undone.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: boolPtr(true),
			IdempotentHint:  true,
			OpenWorldHint:   boolPtr(false),
		},
	}, s.revokeAPIKey)
}

func (s *Server) createAPIKey(ctx context.Context, req *mcp.CallToolRequest, in createKeyInput) (*mcp.CallToolResult, createKeyOutput, error) {
	if strings.TrimSpace(in.Name) == "" {
		return nil, createKeyOutput{}, fmt.Errorf("name is required")
	}
	d, err := s.Store.GetDomainByName(strings.ToLower(strings.TrimSpace(in.Domain)))
	if err != nil {
		return nil, createKeyOutput{}, err
	}
	if d == nil {
		return nil, createKeyOutput{}, fmt.Errorf("domain %s is not registered; create it with create_domain first", in.Domain)
	}
	token, hash, err := store.GenerateAPIKey()
	if err != nil {
		return nil, createKeyOutput{}, err
	}
	id, err := s.Store.CreateAPIKey(in.Name, d.ID, hash)
	if err != nil {
		return nil, createKeyOutput{}, err
	}
	if s.OnKeyCreated != nil {
		s.OnKeyCreated(in.Name, d.Name)
	}
	return nil, createKeyOutput{ID: id, Token: token}, nil
}

func (s *Server) revokeAPIKey(ctx context.Context, req *mcp.CallToolRequest, in revokeKeyInput) (*mcp.CallToolResult, revokeKeyOutput, error) {
	k, err := s.Store.GetAPIKey(in.ID)
	if err != nil {
		return nil, revokeKeyOutput{}, err
	}
	if k == nil {
		return nil, revokeKeyOutput{}, fmt.Errorf("api key %d not found", in.ID)
	}
	var domainName string
	if d, err := s.Store.GetDomain(k.DomainID); err == nil {
		domainName = d.Name
	}
	if err := s.Store.RevokeAPIKey(k.ID); err != nil {
		return nil, revokeKeyOutput{}, err
	}
	if s.OnKeyRevoked != nil {
		s.OnKeyRevoked(k.Name, domainName)
	}
	return nil, revokeKeyOutput{ID: k.ID, Name: k.Name, Domain: domainName, Revoked: true}, nil
}
