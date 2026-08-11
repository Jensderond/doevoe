// Package mcpserver exposes doevoe's admin operations as Model Context
// Protocol tools. Everything here is admin-scoped: authentication (a
// shared bearer token, DOEVOE_MCP_TOKEN) happens at the HTTP layer in
// Handler, not per tool, and the tools are NOT limited to one domain the
// way API keys are — do not mount this handler without that token check.
package mcpserver

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"doevoe/internal/dnscheck"
	"doevoe/internal/store"
)

type Server struct {
	Store       *store.Store
	CheckDomain func(context.Context, *store.Domain) dnscheck.Result
	// EgressIP and DMARCRua parameterize dkimkeys.Records; SystemDomain and
	// Hostname parameterize dkimkeys.SystemRecords for the system domain,
	// mirroring admin.showDomain.
	EgressIP, DMARCRua, SystemDomain, Hostname string
	// Notification hooks, nil-safe (same contract as admin.Admin's).
	OnKeyCreated func(name, domainName string)
	OnKeyRevoked func(name, domainName string)
}

// MCP builds the SDK server with all tools registered. The SDK generates
// each tool's JSON schema from the typed input/output structs and handles
// protocol-version negotiation, so no wire-level code lives in this package.
func (s *Server) MCP() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "doevoe",
		Title:   "doevoe transactional email",
		Version: "1.0.0",
	}, nil)
	s.addEmailTools(srv)
	s.addDomainTools(srv)
	s.addStatsTool(srv)
	return srv
}

func boolPtr(b bool) *bool { return &b }
