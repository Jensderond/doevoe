package dkimkeys

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
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

func Records(domain, selector, pubBase64, egressIP, adminEmail string) []Record {
	return []Record{
		{Type: "TXT (SPF)", Host: "@", Value: fmt.Sprintf("v=spf1 ip4:%s -all", egressIP)},
		{Type: "TXT (DKIM)", Host: selector + "._domainkey", Value: fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubBase64)},
		{Type: "TXT (DMARC)", Host: "_dmarc", Value: fmt.Sprintf("v=DMARC1; p=quarantine; rua=mailto:%s", adminEmail)},
		{Type: "PTR (rDNS)", Host: egressIP,
			Note: "Set at your hosting provider, not in this domain's DNS: reverse DNS for " + egressIP + " must resolve to the server hostname. Doevoe cannot verify this record; Gmail/Outlook will junk mail without it."},
	}
}
