package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

type ECDSAKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	KeyPEM     []byte
}

func NewECDSAKeyPair() (*ECDSAKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("marshaling key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return &ECDSAKeyPair{
		PrivateKey: privateKey,
		KeyPEM:     keyPEM,
	}, nil
}

func GenerateCSR(privateKey *ecdsa.PrivateKey, commonName string) ([]byte, error) {
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	return csrPEM, nil
}

func ParseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR: %w", err)
	}
	return csr, nil
}
