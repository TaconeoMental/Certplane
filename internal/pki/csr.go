package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/TaconeoMental/certplane/internal/dnsname"
)

func GenerateIdentityCSR(privateKey crypto.Signer, identity string) ([]byte, error) {
	identity = strings.TrimSpace(identity)
	if identity == "" {
		return nil, fmt.Errorf("identity is required")
	}

	tpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: identity}}
	return createCSR(privateKey, tpl)
}

func GenerateServiceCSR(privateKey crypto.Signer, names []string) ([]byte, error) {
	canonical, err := dnsname.CanonicalList(names)
	if err != nil {
		return nil, fmt.Errorf("canonicalizing service DNS names: %w", err)
	}
	if len(canonical) == 0 {
		return nil, fmt.Errorf("service CSR requires at least one DNS name")
	}

	tpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: canonical[0]},
		DNSNames: canonical,
	}
	return createCSR(privateKey, tpl)
}

func createCSR(privateKey crypto.Signer, tpl *x509.CertificateRequest) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, tpl, privateKey)
	if err != nil {
		return nil, fmt.Errorf("creating CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func ParseCSRPEM(data []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("unexpected PEM block type %q", block.Type)
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	return csr, nil
}

func PublicKeyFingerprint(publicKey any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshaling public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func CSRFingerprint(csrPEM []byte) string {
	sum := sha256.Sum256(csrPEM)
	return hex.EncodeToString(sum[:])
}

