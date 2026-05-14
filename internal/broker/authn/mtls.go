package authn

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"time"
)

func IdentityFromRequest(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf("no client certificate")
	}
	cert := r.TLS.PeerCertificates[0]
	if err := ValidateClientCertificate(cert); err != nil {
		return "", err
	}
	if cert.Subject.CommonName == "" {
		return "", fmt.Errorf("client certificate common name is empty")
	}
	return cert.Subject.CommonName, nil
}

func ValidateClientCertificate(cert *x509.Certificate) error {
	if cert == nil {
		return fmt.Errorf("nil client certificate")
	}
	if cert.IsCA {
		return fmt.Errorf("client certificate must not be a CA certificate")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("client certificate is outside its validity window")
	}
	if len(cert.ExtKeyUsage) == 0 {
		return fmt.Errorf("client certificate has no extended key usage")
	}
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			return nil
		}
	}
	return fmt.Errorf("client certificate missing clientAuth EKU")
}
