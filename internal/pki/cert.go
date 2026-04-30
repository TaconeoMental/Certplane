package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

func ParseCertificate(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}

func ExpiresWithin(cert *x509.Certificate, d time.Duration) bool {
	return time.Until(cert.NotAfter) <= d
}

func IsExpired(cert *x509.Certificate) bool {
	return time.Now().After(cert.NotAfter)
}
