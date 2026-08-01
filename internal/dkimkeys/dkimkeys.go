package dkimkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

type Record struct{ Type, Host, Value, Note string }

func Generate() (privPEM, pubBase64 string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	privPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", err
	}
	return privPEM, base64.StdEncoding.EncodeToString(pubDER), nil
}

func ParsePrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func PublicKeyTXT(pub *rsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der), nil
}

// PublicB64FromPrivatePEM parses a PEM-encoded RSA private key (as stored on
// a Domain) and returns the bare base64 public-key value suitable for a DKIM
// TXT record's "p=" field (i.e. PublicKeyTXT's output with the
// "v=DKIM1; k=rsa; p=" prefix stripped).
func PublicB64FromPrivatePEM(pemStr string) (string, error) {
	key, err := ParsePrivateKey(pemStr)
	if err != nil {
		return "", err
	}
	txt, err := PublicKeyTXT(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(txt, "v=DKIM1; k=rsa; p="), nil
}

// Records returns the DNS records recommended for a sending domain.
// dmarcRua is the mailbox that receives DMARC aggregate reports (the
// built-in receiver's report address, e.g. "dmarc@<system-domain>"), not
// necessarily the admin's own mailbox.
func Records(domain, selector, pubBase64, egressIP, dmarcRua string) []Record {
	return []Record{
		{Type: "TXT (SPF)", Host: "@", Value: fmt.Sprintf("v=spf1 ip4:%s -all", egressIP)},
		{Type: "TXT (DKIM)", Host: selector + "._domainkey", Value: fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubBase64)},
		{Type: "TXT (DMARC)", Host: "_dmarc", Value: fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:%s", dmarcRua)},
		{Type: "PTR (rDNS)", Host: egressIP,
			Note: "Set at your hosting provider, not in this domain's DNS: reverse DNS for " + egressIP + " must resolve to the server hostname. Doevoe cannot verify this record; Gmail/Outlook will junk mail without it."},
	}
}

// SystemRecords returns the two one-time DNS records for the system domain
// that make doevoe's built-in DMARC report receiver reachable: an MX record
// pointing at the server hostname, and a wildcard TXT record under
// "*._report._dmarc" that authorizes every other domain (per RFC 7489) to
// send its DMARC aggregate reports here.
func SystemRecords(systemDomain, hostname string) []Record {
	return []Record{
		{Type: "MX", Host: "@", Value: "10 " + hostname,
			Note: "Lets DMARC reporters deliver aggregate reports to doevoe's built-in receiver (port 25)."},
		{Type: "TXT (report auth)", Host: "*._report._dmarc", Value: "v=DMARC1",
			Note: "RFC 7489 external-destination authorization: allows every other domain to send its DMARC reports to " + systemDomain + "."},
	}
}
