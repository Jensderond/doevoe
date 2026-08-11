package mcpserver

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"doevoe/internal/dnscheck"
	"doevoe/internal/store"
)

// setup wires a Server to an in-memory MCP client session. CheckDomain is a
// stub returning all-OK; individual tests override srv.CheckDomain before
// the tool call they exercise (the tool handlers read it per call).
func setup(t *testing.T) (*Server, *store.Store, *mcp.ClientSession) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := &Server{
		Store:    st,
		EgressIP: "203.0.113.7",
		DMARCRua: "dmarc@mail.example.com",
		CheckDomain: func(context.Context, *store.Domain) dnscheck.Result {
			return dnscheck.Result{
				SPF:   dnscheck.RecordResult{OK: true},
				DKIM:  dnscheck.RecordResult{OK: true},
				DMARC: dnscheck.RecordResult{OK: true},
			}
		},
	}
	serverT, clientT := mcp.NewInMemoryTransports()
	ss, err := srv.MCP().Connect(context.Background(), serverT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0.0.0"}, nil)
	cs, err := client.Connect(context.Background(), clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return srv, st, cs
}

func toolText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		return ""
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T, want *mcp.TextContent", res.Content[0])
	}
	return tc.Text
}

// callTool invokes a tool and decodes its JSON text content, failing the
// test if the tool returned an error result.
func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if res.IsError {
		t.Fatalf("tool %s errored: %s", name, toolText(t, res))
	}
	out := map[string]any{}
	if err := json.Unmarshal([]byte(toolText(t, res)), &out); err != nil {
		t.Fatalf("tool %s output not JSON: %v", name, err)
	}
	return out
}

// callToolErr invokes a tool expecting an isError result and returns the
// error text.
func callToolErr(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if !res.IsError {
		t.Fatalf("tool %s: expected error result, got %s", name, toolText(t, res))
	}
	return toolText(t, res)
}

func TestGetEmailStatus(t *testing.T) {
	_, st, cs := setup(t)
	d, _ := st.CreateDomain("example.com", "mail1", "PEM")
	id, err := st.EnqueueEmail(&store.Email{
		DomainID: d.ID, From: "hi@example.com", To: "you@other.com",
		Subject: "s", BodyText: "b",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := callTool(t, cs, "get_email_status", map[string]any{"id": id})
	if out["status"] != "queued" || int64(out["id"].(float64)) != id {
		t.Fatalf("got %v", out)
	}
}

func TestGetEmailStatusNotFound(t *testing.T) {
	_, _, cs := setup(t)
	callToolErr(t, cs, "get_email_status", map[string]any{"id": 999})
}

func TestSendEmail(t *testing.T) {
	_, st, cs := setup(t)
	d, _ := st.CreateDomain("example.com", "mail1", "PEM")
	st.SetDomainVerification(d.ID, true, true, true, store.Now())
	out := callTool(t, cs, "send_email", map[string]any{
		"from": "Sender <hi@example.com>", "to": "you@other.com",
		"subject": "hello", "text": "body",
	})
	if out["status"] != "queued" {
		t.Fatalf("got %v", out)
	}
	e, err := st.GetEmail(int64(out["id"].(float64)))
	if err != nil || e.FromName != "Sender" || e.APIKeyID != 0 {
		t.Fatalf("stored email %+v err=%v", e, err)
	}
}

func TestSendEmailUnknownDomain(t *testing.T) {
	_, _, cs := setup(t)
	msg := callToolErr(t, cs, "send_email", map[string]any{
		"from": "hi@nowhere.com", "to": "you@other.com",
		"subject": "hello", "text": "body",
	})
	if msg == "" {
		t.Fatal("expected error text")
	}
}

func TestSendEmailUnverifiedDomainFailsClosed(t *testing.T) {
	_, st, cs := setup(t)
	st.CreateDomain("example.com", "mail1", "PEM") // not verified
	callToolErr(t, cs, "send_email", map[string]any{
		"from": "hi@example.com", "to": "you@other.com",
		"subject": "hello", "text": "body",
	})
}

func TestCreateDomainReturnsDNSRecords(t *testing.T) {
	_, st, cs := setup(t)
	out := callTool(t, cs, "create_domain", map[string]any{"name": "Example.com"})
	if out["name"] != "example.com" {
		t.Fatalf("got %v", out)
	}
	recs, ok := out["dns_records"].([]any)
	if !ok || len(recs) == 0 {
		t.Fatalf("no dns_records in %v", out)
	}
	if d, _ := st.GetDomainByName("example.com"); d == nil {
		t.Fatal("domain not stored")
	}
}

func TestCreateDomainDuplicate(t *testing.T) {
	_, st, cs := setup(t)
	st.CreateDomain("example.com", "mail1", "PEM")
	callToolErr(t, cs, "create_domain", map[string]any{"name": "example.com"})
}

func TestVerifyDomainPersists(t *testing.T) {
	_, st, cs := setup(t)
	callTool(t, cs, "create_domain", map[string]any{"name": "example.com"})
	out := callTool(t, cs, "verify_domain", map[string]any{"name": "example.com"})
	if out["verified"] != true || out["persisted"] != true {
		t.Fatalf("got %v", out)
	}
	d, _ := st.GetDomainByName("example.com")
	if !d.Verified() {
		t.Fatal("verification not persisted")
	}
}

func TestVerifyDomainIndeterminateNotPersisted(t *testing.T) {
	srv, st, cs := setup(t)
	callTool(t, cs, "create_domain", map[string]any{"name": "example.com"})
	d, _ := st.GetDomainByName("example.com")
	st.SetDomainVerification(d.ID, true, true, true, store.Now())
	srv.CheckDomain = func(context.Context, *store.Domain) dnscheck.Result {
		return dnscheck.Result{Indeterminate: true}
	}
	out := callTool(t, cs, "verify_domain", map[string]any{"name": "example.com"})
	if out["indeterminate"] != true || out["persisted"] != false {
		t.Fatalf("got %v", out)
	}
	d, _ = st.GetDomainByName("example.com")
	if !d.Verified() {
		t.Fatal("indeterminate result flipped a verified domain")
	}
}

func TestCreateAndRevokeAPIKey(t *testing.T) {
	srv, st, cs := setup(t)
	var created, revoked bool
	srv.OnKeyCreated = func(name, domainName string) { created = true }
	srv.OnKeyRevoked = func(name, domainName string) { revoked = true }
	st.CreateDomain("example.com", "mail1", "PEM")

	out := callTool(t, cs, "create_api_key", map[string]any{"name": "ci", "domain": "example.com"})
	token, _ := out["token"].(string)
	if !strings.HasPrefix(token, "dv_") {
		t.Fatalf("bad token %q", token)
	}
	if !created {
		t.Fatal("OnKeyCreated not fired")
	}
	if k, _ := st.GetAPIKeyByHash(store.HashAPIKey(token)); k == nil {
		t.Fatal("token does not authenticate")
	}

	id := int64(out["id"].(float64))
	callTool(t, cs, "revoke_api_key", map[string]any{"id": id})
	if !revoked {
		t.Fatal("OnKeyRevoked not fired")
	}
	if k, _ := st.GetAPIKeyByHash(store.HashAPIKey(token)); k != nil {
		t.Fatal("revoked token still authenticates")
	}
}

func TestCreateAPIKeyUnknownDomain(t *testing.T) {
	_, _, cs := setup(t)
	callToolErr(t, cs, "create_api_key", map[string]any{"name": "ci", "domain": "nowhere.com"})
}

func TestRevokeAPIKeyUnknownID(t *testing.T) {
	_, _, cs := setup(t)
	callToolErr(t, cs, "revoke_api_key", map[string]any{"id": 424242})
}

func TestGetSendingStats(t *testing.T) {
	_, st, cs := setup(t)
	d, _ := st.CreateDomain("example.com", "mail1", "PEM")
	st.EnqueueEmail(&store.Email{
		DomainID: d.ID, From: "hi@example.com", To: "you@other.com",
		Subject: "s", BodyText: "b",
	})
	out := callTool(t, cs, "get_sending_stats", map[string]any{"days": 7})
	sum, ok := out["summary"].(map[string]any)
	if !ok {
		t.Fatalf("no summary in %v", out)
	}
	if sum["total"].(float64) != 1 || sum["queued"].(float64) != 1 {
		t.Fatalf("got summary %v", sum)
	}
}
