package webhook

import "time"

// Schedule is the per-delivery retry backoff, deliberately shorter and
// shallower than the email schedule in internal/delivery. A webhook receiver
// that's down is usually down for minutes (a deploy, a restart), not the day
// a greylisting MX can take, and an event that's hours stale is rarely still
// actionable: a consumer that needs day-long durability should poll
// GET /api/v1/emails/{id} instead of relying on us to keep knocking.
// Six attempts spanning ~2h45m in total.
var Schedule = []time.Duration{
	30 * time.Second, 2 * time.Minute, 10 * time.Minute, 30 * time.Minute, 2 * time.Hour,
}

// NextAttempt returns when to retry after the given number of attempts
// (including the one that just failed). ok=false means retries are exhausted.
func NextAttempt(attempts int, now time.Time) (time.Time, bool) {
	if attempts < 1 || attempts > len(Schedule) {
		return time.Time{}, false
	}
	return now.Add(Schedule[attempts-1]), true
}
