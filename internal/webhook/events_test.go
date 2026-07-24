package webhook

import (
	"reflect"
	"testing"
)

func TestValidEvent(t *testing.T) {
	if !ValidEvent(EventEmailSent) {
		t.Error("email.sent must be subscribable")
	}
	// EventTest is only ever addressed at one endpoint from the admin UI, so
	// it must not be selectable as a subscription.
	if ValidEvent(EventTest) {
		t.Error("webhook.test must not be subscribable")
	}
	if ValidEvent("email.opened") {
		t.Error("unknown events must be rejected")
	}
}

func TestValidateURL(t *testing.T) {
	for _, ok := range []string{"https://a.test/hook", "http://10.0.0.4:9000/h"} {
		if err := ValidateURL(ok); err != nil {
			t.Errorf("ValidateURL(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "recv.test/hook", "file:///etc/passwd", "ftp://a.test/x", "https://"} {
		if err := ValidateURL(bad); err == nil {
			t.Errorf("ValidateURL(%q) = nil, want an error", bad)
		}
	}
}

func TestNormalizeEvents(t *testing.T) {
	got, unknown := NormalizeEvents([]string{EventEmailFailed, EventEmailSent, EventEmailSent, " "})
	if unknown != "" {
		t.Fatalf("unknown = %q", unknown)
	}
	// De-duplicated and back in catalogue order, not input order.
	if want := []string{EventEmailSent, EventEmailFailed}; !reflect.DeepEqual(got, want) {
		t.Errorf("events = %v, want %v", got, want)
	}
	if _, unknown := NormalizeEvents([]string{EventEmailSent, "email.opened"}); unknown != "email.opened" {
		t.Errorf("unknown = %q, want email.opened", unknown)
	}
	if got, _ := NormalizeEvents(nil); got != nil {
		t.Errorf("events = %v, want nil", got)
	}
}

func TestEveryEventHasHelpText(t *testing.T) {
	for _, e := range Events {
		if EventHelp[e] == "" {
			t.Errorf("event %q has no help text for the admin UI", e)
		}
	}
}
