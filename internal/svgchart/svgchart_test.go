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
