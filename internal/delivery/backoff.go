package delivery

import "time"

var Schedule = []time.Duration{
	time.Minute, 5 * time.Minute, 15 * time.Minute,
	time.Hour, 4 * time.Hour, 12 * time.Hour, 24 * time.Hour,
}

// NextAttempt returns when to retry after the given number of attempts
// (including the one that just failed). ok=false means retries are exhausted.
func NextAttempt(attempts int, now time.Time) (time.Time, bool) {
	if attempts < 1 || attempts > len(Schedule) {
		return time.Time{}, false
	}
	return now.Add(Schedule[attempts-1]), true
}
