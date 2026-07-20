package delivery

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/store"

	"github.com/emersion/go-smtp"
)

// capturing test SMTP backend
type testBackend struct {
	messages []string
	rejectTo string // when set, RCPT TO this address returns 550
}

type testSession struct{ b *testBackend }

func (b *testBackend) NewSession(_ *smtp.Conn) (smtp.Session, error) { return &testSession{b}, nil }
func (s *testSession) Mail(string, *smtp.MailOptions) error          { return nil }
func (s *testSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	if to == s.b.rejectTo {
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "no such user"}
	}
	return nil
}
func (s *testSession) Data(r io.Reader) error {
	data, _ := io.ReadAll(r)
	s.b.messages = append(s.b.messages, string(data))
	return nil
}
func (s *testSession) Reset()        {}
func (s *testSession) Logout() error { return nil }

func startTestSMTP(t *testing.T, b *testBackend) (host string, port int) {
	t.Helper()
	srv := smtp.NewServer(b)
	srv.Domain = "test.local"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	_, p, _ := net.SplitHostPort(l.Addr().String())
	port, _ = strconv.Atoi(p)
	return "127.0.0.1", port
}

func testSender(port int) *Sender {
	return &Sender{
		Hostname: "mail.example.com",
		Port:     port,
		LookupMX: func(_ context.Context, domain string) ([]*net.MX, error) {
			return []*net.MX{{Host: "127.0.0.1", Pref: 10}}, nil
		},
		TLSConfig: nil, // test server has no STARTTLS
	}
}

func testEmailAndDomain(t *testing.T, to string) (*store.Email, *store.Domain) {
	t.Helper()
	priv, _, err := dkimkeys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return &store.Email{From: "a@example.com", To: to, Subject: "Hi", BodyText: "yo", HeadersJSON: "{}"},
		&store.Domain{Name: "example.com", DKIMSelector: "mail1", DKIMPrivateKey: priv}
}

func TestSendDeliversSignedMessage(t *testing.T) {
	b := &testBackend{}
	_, port := startTestSMTP(t, b)
	e, d := testEmailAndDomain(t, "ok@dest.test")

	res := testSender(port).Send(context.Background(), e, d)
	if res.Err != nil {
		t.Fatalf("send: %+v", res)
	}
	if len(b.messages) != 1 || !strings.Contains(b.messages[0], "DKIM-Signature:") {
		t.Fatalf("server got: %v", b.messages)
	}
	if res.MXHost != "127.0.0.1" || res.Code != 250 {
		t.Errorf("result: %+v", res)
	}
}

func TestSendPermanentRejection(t *testing.T) {
	b := &testBackend{rejectTo: "gone@dest.test"}
	_, port := startTestSMTP(t, b)
	e, d := testEmailAndDomain(t, "gone@dest.test")

	res := testSender(port).Send(context.Background(), e, d)
	if res.Err == nil || Classify(res.Err) != ClassPerm || res.Code != 550 {
		t.Fatalf("want 550 perm, got %+v", res)
	}
}

func TestSendConnectionRefusedIsTemp(t *testing.T) {
	e, d := testEmailAndDomain(t, "x@dest.test")
	res := testSender(1).Send(context.Background(), e, d) // port 1: refused
	if res.Err == nil || Classify(res.Err) != ClassTemp {
		t.Fatalf("want temp error, got %+v", res)
	}
}
