package delivery

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/store"

	"github.com/emersion/go-msgauth/dkim"
)

var testTime = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

func TestBuildMessageMultipart(t *testing.T) {
	e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi",
		BodyText: "plain", BodyHTML: "<b>html</b>", HeadersJSON: `{"X-Campaign":"welcome"}`}
	msg, err := BuildMessage(e, "mail.example.com", testTime)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"From: a@example.com\r\n", "To: b@dest.test\r\n", "Subject: Hi\r\n",
		"multipart/alternative", "X-Campaign: welcome\r\n", "@mail.example.com>", "plain", "<b>html</b>"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing %q", want)
		}
	}
	if strings.Contains(strings.ReplaceAll(msg, "\r\n", ""), "\n") {
		t.Error("bare LF found; DKIM requires CRLF")
	}
}

func TestBuildMessageRejectsHeaderInjectionInSubject(t *testing.T) {
	e := &store.Email{From: "a@example.com", To: "b@dest.test",
		Subject: "Hi\r\nBcc: evil@example.com", BodyText: "plain", HeadersJSON: "{}"}
	if _, err := BuildMessage(e, "mail.example.com", testTime); err == nil {
		t.Fatal("want error for CRLF injection in Subject, got nil")
	}
}

func TestBuildMessageRejectsHeaderInjectionInCustomHeader(t *testing.T) {
	e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi", BodyText: "plain",
		HeadersJSON: `{"X-Campaign":"welcome\r\nBcc: evil@example.com"}`}
	if _, err := BuildMessage(e, "mail.example.com", testTime); err == nil {
		t.Fatal("want error for CRLF injection in custom header value, got nil")
	}
}

func TestBuildMessageRejectsReservedCustomHeader(t *testing.T) {
	for _, name := range []string{"Bcc", "bcc", "From", "DKIM-Signature", "Content-Type"} {
		e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi", BodyText: "plain",
			HeadersJSON: fmt.Sprintf(`{%q:"x"}`, name)}
		if _, err := BuildMessage(e, "mail.example.com", testTime); err == nil {
			t.Errorf("header %q: want error for reserved custom header, got nil", name)
		}
	}
}

func TestSignMessageVerifies(t *testing.T) {
	priv, _, err := dkimkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	d := &store.Domain{Name: "example.com", DKIMSelector: "mail1", DKIMPrivateKey: priv}
	e := &store.Email{From: "a@example.com", To: "b@dest.test", Subject: "Hi", BodyText: "plain", HeadersJSON: "{}"}
	msg, _ := BuildMessage(e, "mail.example.com", testTime)
	signed, err := SignMessage(msg, d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(signed, "DKIM-Signature:") {
		t.Fatal("no DKIM-Signature header")
	}
	// Round-trip verify with the same library, resolving the public key locally.
	verifications, err := dkim.VerifyWithOptions(strings.NewReader(signed), &dkim.VerifyOptions{
		LookupTXT: func(name string) ([]string, error) {
			key, _ := dkimkeys.ParsePrivateKey(priv)
			pub, _ := dkimkeys.PublicKeyTXT(&key.PublicKey)
			return []string{pub}, nil
		},
	})
	if err != nil || len(verifications) != 1 || verifications[0].Err != nil {
		t.Fatalf("verify: %v %+v", err, verifications)
	}
}
