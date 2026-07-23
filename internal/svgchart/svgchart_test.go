package svgchart

import (
	"strings"
	"testing"
)

func TestStackedBarsRendersColoredRects(t *testing.T) {
	out := string(StackedBars([]DayBar{
		{Label: "07-01", Sent: 2, Failed: 1},
		{Label: "07-02", Sent: 3, Failed: 0},
	}))
	if !strings.Contains(out, "<svg") {
		t.Error("expected an <svg> element")
	}
	if !strings.Contains(out, "var(--green)") {
		t.Error("expected green (sent) bars")
	}
	if !strings.Contains(out, "var(--red)") {
		t.Error("expected red (failed) bars")
	}
	if !strings.Contains(out, `role="img"`) {
		t.Error("expected role=img for accessibility")
	}
}

func TestStackedBarsEmptyIsPlaceholder(t *testing.T) {
	if !strings.Contains(string(StackedBars(nil)), "No data") {
		t.Error("empty input should render the placeholder")
	}
}

func TestStackedBarsAllZeroIsPlaceholder(t *testing.T) {
	out := string(StackedBars([]DayBar{{Label: "07-01"}, {Label: "07-02"}}))
	if !strings.Contains(out, "No data") {
		t.Errorf("all-zero input should render placeholder, got %q", out)
	}
}

func TestHBarsScalesAndEscapes(t *testing.T) {
	out := string(HBars([]HBar{
		{Label: "<script>", Value: 10},
		{Label: "b.test", Value: 5},
	}))
	if strings.Contains(out, "<script>") {
		t.Error("label must be HTML-escaped")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected escaped label")
	}
	if !strings.Contains(out, "width:100.0%") {
		t.Error("largest bar should be full width")
	}
	if !strings.Contains(out, "width:50.0%") {
		t.Error("half-value bar should be 50%")
	}
}

func TestHBarsEmptyIsPlaceholder(t *testing.T) {
	if !strings.Contains(string(HBars(nil)), "No data") {
		t.Error("empty input should render the placeholder")
	}
}

func TestStackedBarsPerDayTooltip(t *testing.T) {
	out := string(StackedBars([]DayBar{{Label: "07-01", Sent: 2, Failed: 1}}))
	if !strings.Contains(out, "<title>07-01: 2 sent, 1 failed</title>") {
		t.Errorf("expected per-day tooltip, got %q", out)
	}
	// A full-height transparent hit area keeps empty/short days hoverable.
	if !strings.Contains(out, `pointer-events="all"`) {
		t.Error("expected a full-column hover hit area")
	}
}

func TestHBarsRowTooltip(t *testing.T) {
	out := string(HBars([]HBar{{Label: "b.test", Value: 5}}))
	if !strings.Contains(out, `title="b.test: 5"`) {
		t.Errorf("expected a full-detail row tooltip, got %q", out)
	}
}

func TestHBarsRowTooltipEscapes(t *testing.T) {
	out := string(HBars([]HBar{{Label: `"x"`, Value: 1}}))
	if strings.Contains(out, `title=""x": 1"`) {
		t.Error("row tooltip must escape quotes in the label")
	}
}
