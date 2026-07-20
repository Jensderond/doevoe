package delivery

import (
	"testing"
	"time"
)

func TestNextAttemptSchedule(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	next, ok := NextAttempt(1, now)
	if !ok || next != now.Add(time.Minute) {
		t.Fatalf("attempt 1: %v %v", next, ok)
	}
	next, ok = NextAttempt(7, now)
	if !ok || next != now.Add(24*time.Hour) {
		t.Fatalf("attempt 7: %v %v", next, ok)
	}
	if _, ok := NextAttempt(8, now); ok {
		t.Fatal("attempt 8 must be exhausted")
	}
}
