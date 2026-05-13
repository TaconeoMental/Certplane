package pki

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/TaconeoMental/certplane/internal/dnsname"
)

func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}

func EncodeCertPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

func ExpiresWithin(cert *x509.Certificate, d time.Duration) bool {
	return time.Until(cert.NotAfter) <= d
}

func IsExpired(cert *x509.Certificate) bool { return time.Now().After(cert.NotAfter) }

func CertificateMatchesPrivateKey(cert *x509.Certificate, key crypto.Signer) error {
	certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshaling certificate public key: %w", err)
	}
	keyPubDER, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return fmt.Errorf("marshaling private key public key: %w", err)
	}
	if !bytes.Equal(certPubDER, keyPubDER) {
		return fmt.Errorf("certificate public key does not match private key")
	}
	return nil
}

func SerialString(n *big.Int) string {
	if n == nil {
		return ""
	}
	return n.Text(16)
}

func CertificateHasExactDNSNames(cert *x509.Certificate, expected []string) error {
	actual, err := dnsname.CanonicalList(cert.DNSNames)
	if err != nil {
		return fmt.Errorf("canonicalizing certificate DNS names: %w", err)
	}
	exp, err := dnsname.CanonicalList(expected)
	if err != nil {
		return fmt.Errorf("canonicalizing expected DNS names: %w", err)
	}
	if !dnsname.EqualSet(actual, exp) {
		return fmt.Errorf("certificate DNS names %v do not match expected %v", actual, exp)
	}
	return nil
}

