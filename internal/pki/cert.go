package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
)

type ECDSAKeyPair struct {
	PublicKey  *ecdsa.PublicKey
	PrivateKey *ecdsa.PrivateKey
}

func NewECDSAKeyPair() (*ECDSAKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &ECDSAKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

func GenerateCSR(privateKey *ecdsa.PrivateKey, commonName string) (string, error) {
	// TODO: necesito mas info??
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}

	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return "", err
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrBytes,
	})

	return string(csrPEM), nil
}
