package mcpserver

import (
	"context"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"doevoe/internal/store"
)

type statsInput struct {
	Days int `json:"days,omitempty" jsonschema:"how many days back to aggregate (default 30, max 365)"`
}

// Local mirrors of the store's stats types: the store structs carry no json
// tags, and the MCP output schema should not silently change if they gain
// some.
type statsSummary struct {
	Sent        int     `json:"sent"`
	Failed      int     `json:"failed"`
	Queued      int     `json:"queued"`
	Canceled    int     `json:"canceled"`
	Total       int     `json:"total"`
	SuccessRate float64 `json:"success_rate"`
}

type statsDay struct {
	Date   string `json:"date"`
	Sent   int    `json:"sent"`
	Failed int    `json:"failed"`
}

type statsDomain struct {
	Domain string `json:"domain"`
	Sent   int    `json:"sent"`
	Failed int    `json:"failed"`
}

type statsReason struct {
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type statsOutput struct {
	Days           int           `json:"days"`
	Summary        statsSummary  `json:"summary"`
	Daily          []statsDay    `json:"daily"`
	Domains        []statsDomain `json:"domains"`
	FailureReasons []statsReason `json:"top_failure_reasons"`
}

func (s *Server) addStatsTool(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "get_sending_stats",
		Description: "Aggregate sending statistics over the last N days: totals by status, daily volume, per-domain volume, and top failure reasons.",
		Annotations: &mcp.ToolAnnotations{
			ReadOnlyHint:  true,
			OpenWorldHint: boolPtr(false),
		},
	}, s.getSendingStats)
}

func (s *Server) getSendingStats(ctx context.Context, req *mcp.CallToolRequest, in statsInput) (*mcp.CallToolResult, statsOutput, error) {
	days := in.Days
	if days <= 0 {
		days = 30
	}
	if days > 365 {
		days = 365
	}
	now := time.Now().UTC()
	// Upper bound is tomorrow, not now: the store ranges are half-open
	// [from, to) on RFC3339 strings, and "now" would exclude emails
	// created within the current second.
	from := store.FmtTime(now.AddDate(0, 0, -days))
	to := store.FmtTime(now.AddDate(0, 0, 1))

	sum, err := s.Store.SummaryStats(from, to)
	if err != nil {
		return nil, statsOutput{}, err
	}
	daily, err := s.Store.DailyVolume(from, to)
	if err != nil {
		return nil, statsOutput{}, err
	}
	domains, err := s.Store.DomainVolume(from, to)
	if err != nil {
		return nil, statsOutput{}, err
	}
	reasons, err := s.Store.FailureReasons(from, to, 8)
	if err != nil {
		return nil, statsOutput{}, err
	}

	out := statsOutput{
		Days: days,
		Summary: statsSummary{
			Sent: sum.Sent, Failed: sum.Failed, Queued: sum.Queued,
			Canceled: sum.Canceled, Total: sum.Total, SuccessRate: sum.SuccessRate,
		},
	}
	for _, d := range daily {
		out.Daily = append(out.Daily, statsDay{Date: d.Date, Sent: d.Sent, Failed: d.Failed})
	}
	for _, d := range domains {
		out.Domains = append(out.Domains, statsDomain{Domain: d.DomainName, Sent: d.Sent, Failed: d.Failed})
	}
	for _, r := range reasons {
		out.FailureReasons = append(out.FailureReasons, statsReason{Reason: r.Reason, Count: r.Count})
	}
	return nil, out, nil
}
