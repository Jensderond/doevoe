package mcpserver

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Handler returns the HTTP handler for the MCP endpoint: the SDK's
// Streamable HTTP transport wrapped in bearer-token auth. One *mcp.Server
// is shared across requests; the SDK manages per-connection protocol
// negotiation and any session state internally.
func Handler(s *Server, token string) http.Handler {
	m := s.MCP()
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return m }, nil)
	return bearerAuth(token, h)
}

// bearerAuth admits only requests carrying "Authorization: Bearer <token>".
// An empty configured token rejects everything rather than allowing
// everything: main only mounts the endpoint when a token is set, but this
// must stay fail-closed even if that changes.
func bearerAuth(token string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		got := strings.TrimPrefix(header, "Bearer ")
		if token == "" || got == "" || got == header ||
			subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
