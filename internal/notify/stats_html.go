package notify

import (
	"fmt"
	"html/template"
	"log/slog"
	"strings"
	"time"

	"doevoe/internal/store"
)

// The HTML alternative for the monthly stats email. It restyles the same
// numbers the plain-text body carries (see StatsTick — both are built in one
// pass) after the admin UI's "airmail ledger" look, but self-contained the way
// email HTML has to be: fixed light palette, table layout, every style inline,
// no external assets. Lines are kept short because the body is written to the
// wire verbatim (no quoted-printable), and SMTP caps lines at 998 bytes.

type statsHTMLData struct {
	Month      string // "2026-07", as in the subject and text body
	MonthLabel string // "July 2026"
	BaseURL    string
	Rows       []statsRowData
	Reasons    []store.ReasonCount
	DNS        []dnsStatusRow
}

type statsRowData struct {
	Domain       string
	NoActivity   bool // active last month, silent in the reported one
	Sent, Failed int
	Rate         string // "98.3%", "" when the month had no attempts
	Prev         string // "12 sent, 1 failed (92.3% delivered)" or "no activity"
	Delta        string // "+50.0pt", "" when either month lacks a rate
	DeltaGood    bool
}

type dnsStatusRow struct {
	Name     string
	Verified bool
}

// statsHTMLRow mirrors fmtCounts/fmtComparison for the HTML table: the same
// numbers and comparison rules, split into columns instead of one line. It
// must be called before StatsTick deletes st's entry from prev.
func statsHTMLRow(st store.DomainStats, noActivity bool, prev map[string]store.DomainStats) statsRowData {
	row := statsRowData{Domain: st.DomainName, NoActivity: noActivity, Sent: st.Sent, Failed: st.Failed}
	if rate, ok := deliveryRate(st); ok {
		row.Rate = fmt.Sprintf("%.1f%%", rate)
	}
	p, ok := prev[st.DomainName]
	if !ok {
		row.Prev = "no activity"
		return row
	}
	row.Prev = fmtCounts(p)
	cur, okCur := deliveryRate(st)
	old, okOld := deliveryRate(p)
	if okCur && okOld {
		row.Delta = fmt.Sprintf("%+.1fpt", cur-old)
		row.DeltaGood = cur >= old
	}
	return row
}

func monthLabel(month string) string {
	t, err := time.Parse("2006-01", month)
	if err != nil {
		return month
	}
	return t.Format("January 2006")
}

// renderStatsHTML fails open: the plain-text body is the canonical report, so
// a rendering error degrades the email to text-only instead of blocking it.
func renderStatsHTML(data statsHTMLData) string {
	var b strings.Builder
	if err := statsTemplate.Execute(&b, data); err != nil {
		slog.Error("notifier: rendering stats html failed", "err", err)
		return ""
	}
	return b.String()
}

var statsTemplate = template.Must(template.New("stats").Parse(statsTemplateSrc))

const statsTemplateSrc = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>doevoe monthly stats {{.Month}}</title>
</head>
<body style="margin:0;padding:0;background-color:#f5f4ef;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f5f4ef;">
<tr><td align="center" style="padding:24px 12px;">
<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="width:600px;max-width:100%;background-color:#ffffff;border:1px solid #e2dfd6;border-radius:6px;">
<tr>
<td style="height:6px;line-height:6px;font-size:2px;border-radius:6px 6px 0 0;background-color:#b8382e;background-image:repeating-linear-gradient(-45deg,#b8382e 0 9px,#f5f4ef 9px 18px,#2b5cc9 18px 27px,#f5f4ef 27px 36px);">&nbsp;</td>
</tr>
<tr><td style="padding:22px 28px 0;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0">
<tr>
<td style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:18px;font-weight:700;letter-spacing:-.02em;color:#1d2530;">doevoe<span style="color:#b8382e;">_</span></td>
<td align="right" style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:13px;color:#5f6878;">monthly stats</td>
</tr>
</table>
<div style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:24px;font-weight:700;letter-spacing:-.02em;color:#1d2530;padding:14px 0 2px;">{{.MonthLabel}}</div>
</td></tr>
<tr><td style="padding:14px 28px 0;">
<div style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#5f6878;border-bottom:1px solid #e2dfd6;padding-bottom:6px;">Per domain</div>
{{if .Rows}}
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
<tr>
<td style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:12px;color:#5f6878;padding:8px 0 4px;">Domain</td>
<td align="right" style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:12px;color:#5f6878;padding:8px 0 4px 12px;">Sent</td>
<td align="right" style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:12px;color:#5f6878;padding:8px 0 4px 12px;">Failed</td>
<td align="right" style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:12px;color:#5f6878;padding:8px 0 4px 12px;">Delivered</td>
<td align="right" style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:12px;color:#5f6878;padding:8px 0 4px 12px;">Prev month</td>
</tr>
{{range .Rows}}
<tr>
<td style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:13px;color:#1d2530;padding:6px 0;border-top:1px solid #f0eee7;overflow-wrap:break-word;">{{.Domain}}</td>
{{if .NoActivity}}
<td colspan="3" align="right" style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:13px;font-style:italic;color:#5f6878;padding:6px 0 6px 12px;border-top:1px solid #f0eee7;">no activity</td>
{{else}}
<td align="right" style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:13px;color:#1d2530;padding:6px 0 6px 12px;border-top:1px solid #f0eee7;">{{.Sent}}</td>
<td align="right" style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:13px;padding:6px 0 6px 12px;border-top:1px solid #f0eee7;{{if gt .Failed 0}}color:#b8382e;{{else}}color:#1d2530;{{end}}">{{.Failed}}</td>
<td align="right" style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:13px;color:#1d2530;padding:6px 0 6px 12px;border-top:1px solid #f0eee7;">{{.Rate}}</td>
{{end}}
<td align="right" style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:12px;color:#5f6878;padding:6px 0 6px 12px;border-top:1px solid #f0eee7;">
{{- .Prev}}{{if .Delta}} <span style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;{{if .DeltaGood}}color:#1e7a4b;{{else}}color:#b8382e;{{end}}">{{.Delta}}</span>{{end}}</td>
</tr>
{{end}}
</table>
{{else}}
<div style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:13px;font-style:italic;color:#5f6878;padding:10px 0 2px;">No email activity.</div>
{{end}}
</td></tr>
{{if .Reasons}}
<tr><td style="padding:18px 28px 0;">
<div style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#5f6878;border-bottom:1px solid #e2dfd6;padding-bottom:6px;">Top failure reasons</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
{{range .Reasons}}
<tr>
<td width="48" align="right" valign="top" style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:13px;color:#b8382e;padding:6px 10px 6px 0;border-top:1px solid #f0eee7;white-space:nowrap;">{{.Count}}&#215;</td>
<td style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:12px;color:#1d2530;padding:6px 0;border-top:1px solid #f0eee7;overflow-wrap:break-word;">{{.Reason}}</td>
</tr>
{{end}}
</table>
</td></tr>
{{end}}
<tr><td style="padding:18px 28px 0;">
<div style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:11px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:#5f6878;border-bottom:1px solid #e2dfd6;padding-bottom:6px;">DNS verification</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
{{range .DNS}}
<tr>
<td style="font-family:ui-monospace,'SF Mono',Menlo,Consolas,monospace;font-size:13px;color:#1d2530;padding:6px 0;border-top:1px solid #f0eee7;overflow-wrap:break-word;">{{.Name}}</td>
{{if .Verified}}
<td align="right" style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:12px;font-weight:600;color:#1e7a4b;padding:6px 0 6px 12px;border-top:1px solid #f0eee7;">OK</td>
{{else}}
<td align="right" style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:12px;font-weight:600;color:#b8382e;padding:6px 0 6px 12px;border-top:1px solid #f0eee7;">NOT VERIFIED &#8212; sending blocked</td>
{{end}}
</tr>
{{end}}
</table>
</td></tr>
<tr><td style="padding:22px 28px 24px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-top:1px solid #e2dfd6;">
<tr><td style="padding-top:14px;">
<a href="{{.BaseURL}}/admin/" style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:13px;font-weight:600;color:#2b5cc9;text-decoration:none;">Open the doevoe admin &#8594;</a>
</td></tr>
<tr><td style="font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:11px;color:#5f6878;padding-top:8px;">
Sent once a month by your doevoe instance.
</td></tr>
</table>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
`
