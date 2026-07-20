package delivery

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"doevoe/internal/dkimkeys"
	"doevoe/internal/store"

	"github.com/emersion/go-smtp"
)

// capturing test SMTP backend
type testBackend struct {
	messages  []string
	rejectTo  string        // when set, RCPT TO this address returns 550
	dataDelay time.Duration // when set, Data sleeps this long before responding
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
	if s.b.dataDelay > 0 {
		time.Sleep(s.b.dataDelay)
	}
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

// startTestSMTPTLS is like startTestSMTP but enables STARTTLS advertisement
// on the server using the given certificate.
func startTestSMTPTLS(t *testing.T, b *testBackend, cert tls.Certificate) (host string, port int) {
	t.Helper()
	srv := smtp.NewServer(b)
	srv.Domain = "test.local"
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
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

// generateSelfSignedCert returns a self-signed cert/key pair valid for
// 127.0.0.1, for use as an in-process test SMTP server's STARTTLS cert.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
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

func TestSendSTARTTLSSuccess(t *testing.T) {
	cert := generateSelfSignedCert(t)
	b := &testBackend{}
	_, port := startTestSMTPTLS(t, b, cert)
	e, d := testEmailAndDomain(t, "ok@dest.test")

	sender := testSender(port)
	sender.TLSConfig = func(host string) *tls.Config {
		return &tls.Config{ServerName: host, InsecureSkipVerify: true}
	}

	res := sender.Send(context.Background(), e, d)
	if res.Err != nil {
		t.Fatalf("send: %+v", res)
	}
	if !res.TLS {
		t.Error("want Result.TLS = true for successful STARTTLS")
	}
	if len(b.messages) != 1 || !strings.Contains(b.messages[0], "DKIM-Signature:") {
		t.Fatalf("server got: %v", b.messages)
	}
}

func TestSendSTARTTLSHandshakeFailureFallsBackToPlaintext(t *testing.T) {
	cert := generateSelfSignedCert(t)
	b := &testBackend{}
	_, port := startTestSMTPTLS(t, b, cert)
	e, d := testEmailAndDomain(t, "ok@dest.test")

	sender := testSender(port)
	// No InsecureSkipVerify and no trusted CA for this self-signed cert, so
	// the handshake forced by connect's post-STARTTLS Hello must fail.
	sender.TLSConfig = func(host string) *tls.Config {
		return &tls.Config{ServerName: host}
	}

	res := sender.Send(context.Background(), e, d)
	if res.Err != nil {
		t.Fatalf("want opportunistic plaintext fallback to succeed, got: %+v", res)
	}
	if res.TLS {
		t.Error("want Result.TLS = false after handshake-failure downgrade")
	}
	if len(b.messages) != 1 || !strings.Contains(b.messages[0], "DKIM-Signature:") {
		t.Fatalf("server got: %v", b.messages)
	}
}

// TestSendOverallTimeoutBoundsAllIO verifies that Sender.OverallTimeout is a
// hard, socket-level cap that bounds every phase of Send - not just the
// commandTimeout/submissionTimeout window inside an already-established
// *smtp.Client. It uses a struct-literal Sender (OverallTimeout left unset in
// testSender, then overridden to a tiny value here) against a server whose
// Data handler stalls for longer than that timeout, so the deadline must
// expire mid-conversation (well after dial/EHLO, which are near-instant
// against a local server) rather than at connect time. This is the same
// mechanism (conn.SetDeadline in connect's dial closure) that bounds
// smtp.NewClientStartTLS's internal handshake in the STARTTLS tests above;
// TestSendSTARTTLSSuccess/TestSendSTARTTLSHandshakeFailureFallsBackToPlaintext
// passing alongside this confirms the default 30m OverallTimeout doesn't
// interfere with normal (fast) STARTTLS handshakes.
func TestSendOverallTimeoutBoundsAllIO(t *testing.T) {
	b := &testBackend{dataDelay: 2 * time.Second}
	_, port := startTestSMTP(t, b)
	e, d := testEmailAndDomain(t, "ok@dest.test")

	sender := testSender(port)
	sender.OverallTimeout = 300 * time.Millisecond

	start := time.Now()
	res := sender.Send(context.Background(), e, d)
	elapsed := time.Since(start)

	if elapsed > time.Second {
		t.Fatalf("Send took %v, want bounded by the 300ms OverallTimeout (with margin), well under the 2s Data stall", elapsed)
	}
	if res.Err == nil {
		t.Fatalf("want a non-nil error when OverallTimeout expires mid-conversation, got success: %+v", res)
	}
	if Classify(res.Err) != ClassTemp {
		t.Fatalf("want temp-classified error (deadline/timeout, not a real SMTP rejection), got %+v (class %v)", res.Err, Classify(res.Err))
	}
}

func TestSendConnectionRefusedIsTemp(t *testing.T) {
	e, d := testEmailAndDomain(t, "x@dest.test")
	res := testSender(1).Send(context.Background(), e, d) // port 1: refused
	if res.Err == nil || Classify(res.Err) != ClassTemp {
		t.Fatalf("want temp error, got %+v", res)
	}
}
