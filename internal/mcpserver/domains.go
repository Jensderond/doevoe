package mcpserver

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/domains"
	"doevoe/internal/store"
)

type createDomainInput struct {
	Name string `json:"name" jsonschema:"the domain to send from, e.g. example.com"`
}

type dnsRecord struct {
	Type  string `json:"type"`
	Host  string `json:"host"`
	Value string `json:"value"`
	Note  string `json:"note,omitempty"`
}

type createDomainOutput struct {
	ID      int64       `json:"id"`
	Name    string      `json:"name"`
	Records []dnsRecord `json:"dns_records" jsonschema:"the DNS records to add at the domain's DNS provider before verify_domain can pass"`
}

type verifyDomainInput struct {
	Name string `json:"name" jsonschema:"a domain previously created with create_domain"`
}

type recordCheck struct {
	OK       bool   `json:"ok"`
	Found    string `json:"found,omitempty"`
	Expected string `json:"expected,omitempty"`
}

type verifyDomainOutput struct {
	Name          string      `json:"name"`
	Verified      bool        `json:"verified"`
	Indeterminate bool        `json:"indeterminate" jsonschema:"true when a DNS lookup failed transiently; the result was not persisted, retry later"`
	Persisted     bool        `json:"persisted"`
	SPF           recordCheck `json:"spf"`
	DKIM          recordCheck `json:"dkim"`
	DMARC         recordCheck `json:"dmarc"`
}

func (s *Server) addDomainTools(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "create_domain",
		Description: "Register a sending domain: generates a DKIM keypair and returns the SPF/DKIM/DMARC DNS records to add at the DNS provider. Run verify_domain after the records are in place.",
		Annotations: &mcp.ToolAnnotations{
			DestructiveHint: boolPtr(false),
			IdempotentHint:  false,
			OpenWorldHint:   boolPtr(false),
		},
	}, s.createDomain)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "verify_domain",
		Description: "Check a domain's SPF, DKIM, and DMARC DNS records against the expected values and persist the result. Sending is only allowed from fully verified domains.",
		Annotations: &mcp.ToolAnnotations{
			IdempotentHint: true,
			OpenWorldHint:  boolPtr(false),
		},
	}, s.verifyDomain)
}

func (s *Server) createDomain(ctx context.Context, req *mcp.CallToolRequest, in createDomainInput) (*mcp.CallToolResult, createDomainOutput, error) {
	name := strings.ToLower(strings.TrimSpace(in.Name))
	// Pre-check for a friendly message; the UNIQUE index on domains.name
	// still backstops a race.
	if existing, err := s.Store.GetDomainByName(name); err != nil {
		return nil, createDomainOutput{}, err
	} else if existing != nil {
		return nil, createDomainOutput{}, fmt.Errorf("domain %s already exists (id %d)", name, existing.ID)
	}
	d, err := domains.Create(s.Store, in.Name)
	if err != nil {
		return nil, createDomainOutput{}, err
	}
	out, err := s.domainRecords(d)
	if err != nil {
		return nil, createDomainOutput{}, err
	}
	return nil, out, nil
}

func (s *Server) domainRecords(d *store.Domain) (createDomainOutput, error) {
	pub, err := dkimkeys.PublicB64FromPrivatePEM(d.DKIMPrivateKey)
	if err != nil {
		return createDomainOutput{}, err
	}
	records := dkimkeys.Records(d.Name, d.DKIMSelector, pub, s.EgressIP, s.DMARCRua)
	// Same rule as admin.showDomain: the system domain additionally needs
	// the one-time MX/TXT records that make the built-in DMARC report
	// receiver reachable.
	if d.Name == s.SystemDomain {
		records = append(records, dkimkeys.SystemRecords(s.SystemDomain, s.Hostname)...)
	}
	out := createDomainOutput{ID: d.ID, Name: d.Name}
	for _, r := range records {
		out.Records = append(out.Records, dnsRecord{Type: r.Type, Host: r.Host, Value: r.Value, Note: r.Note})
	}
	return out, nil
}

func (s *Server) verifyDomain(ctx context.Context, req *mcp.CallToolRequest, in verifyDomainInput) (*mcp.CallToolResult, verifyDomainOutput, error) {
	name := strings.ToLower(strings.TrimSpace(in.Name))
	d, err := s.Store.GetDomainByName(name)
	if err != nil {
		return nil, verifyDomainOutput{}, err
	}
	if d == nil {
		return nil, verifyDomainOutput{}, fmt.Errorf("domain %s is not registered; create it with create_domain first", name)
	}
	res, persisted, err := domains.Verify(ctx, s.Store, domains.CheckFunc(s.CheckDomain), d)
	if err != nil {
		return nil, verifyDomainOutput{}, err
	}
	return nil, verifyDomainOutput{
		Name:          d.Name,
		Verified:      res.AllOK(),
		Indeterminate: res.Indeterminate,
		Persisted:     persisted,
		SPF:           recordCheck{OK: res.SPF.OK, Found: res.SPF.Found, Expected: res.SPF.Expected},
		DKIM:          recordCheck{OK: res.DKIM.OK, Found: res.DKIM.Found, Expected: res.DKIM.Expected},
		DMARC:         recordCheck{OK: res.DMARC.OK, Found: res.DMARC.Found, Expected: res.DMARC.Expected},
	}, nil
}
