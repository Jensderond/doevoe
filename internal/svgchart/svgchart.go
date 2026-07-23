// Package svgchart renders small, dependency-free charts as HTML/SVG strings
// for the admin dashboard. Colors reference the CSS custom properties defined
// in the admin stylesheet, so charts follow the light/dark theme automatically.
package svgchart

import (
	"fmt"
	"html/template"
	"strings"
)

// DayBar is one day's column in a StackedBars chart.
type DayBar struct {
	Label        string
	Sent, Failed int
}

// HBar is one row in an HBars chart.
type HBar struct {
	Label string
	Value int
}

func placeholder() template.HTML {
	return template.HTML(`<p class="empty">No data for this range.</p>`)
}

// StackedBars renders daily volume as stacked columns: sent (green) at the
// bottom, failed (red) above it. Returns a placeholder when there is nothing
// to plot.
func StackedBars(days []DayBar) template.HTML {
	max := 0
	for _, d := range days {
		if t := d.Sent + d.Failed; t > max {
			max = t
		}
	}
	if max == 0 {
		return placeholder()
	}
	const (
		plotH = 120.0 // plot area height in viewBox units
		step  = 20.0  // column pitch
		gap   = 3.0   // gap each side of a bar
	)
	w := float64(len(days)) * step
	var b strings.Builder
	// No inline width/height: the .chart CSS rule fixes the rendered height so
	// the chart stays a consistent size whether the range is 7 or 90 days
	// (preserveAspectRatio="none" lets the bars stretch to fill that box).
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" class="chart" role="img" aria-label="Daily email volume: sent and failed" preserveAspectRatio="none">`, w, plotH)
	b.WriteString(`<title>Daily email volume</title>`)
	for i, d := range days {
		x := float64(i)*step + gap
		bw := step - gap*2
		sentH := float64(d.Sent) / float64(max) * plotH
		failH := float64(d.Failed) / float64(max) * plotH
		if sentH > 0 {
			fmt.Fprintf(&b, `<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="var(--green)"/>`,
				x, plotH-sentH, bw, sentH)
		}
		if failH > 0 {
			fmt.Fprintf(&b, `<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="var(--red)"/>`,
				x, plotH-sentH-failH, bw, failH)
		}
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

// HBars renders horizontal bars as semantic HTML (so long labels ellipsize),
// with the largest value scaled to full track width. Returns a placeholder
// when there is nothing to plot.
func HBars(bars []HBar) template.HTML {
	max := 0
	for _, x := range bars {
		if x.Value > max {
			max = x.Value
		}
	}
	if max == 0 {
		return placeholder()
	}
	var b strings.Builder
	b.WriteString(`<div class="hbars">`)
	for _, x := range bars {
		pct := float64(x.Value) / float64(max) * 100
		label := template.HTMLEscapeString(x.Label)
		fmt.Fprintf(&b, `<div class="hbar"><span class="hbar-label" title="%s">%s</span><span class="hbar-track"><span class="hbar-fill" style="width:%.1f%%"></span></span><span class="hbar-value">%d</span></div>`,
			label, label, pct, x.Value)
	}
	b.WriteString(`</div>`)
	return template.HTML(b.String())
}
