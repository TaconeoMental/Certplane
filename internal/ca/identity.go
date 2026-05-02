package ca

import (
	"context"
	"crypto/x509"
)

type EnrollmentRequest struct {
	CSR   *x509.CertificateRequest
	Token string
}

type IdentityCertificate struct {
	Certificate *x509.Certificate
	CertPEM     []byte
	KeyPEM      []byte
}

type IdentityCA interface {
	Enroll(ctx context.Context, req *EnrollmentRequest) (*IdentityCertificate, error)
	Renew(ctx context.Context, certPEM []byte, keyPEM []byte, rootCAPEM []byte) (*IdentityCertificate, error)
	Revoke(ctx context.Context, serial string) error
}
