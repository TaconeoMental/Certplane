package ca

import (
	"context"
	"crypto/x509"
	"time"
)

type EnrollmentRequest struct {
	CSRPEM []byte
	Token  string
}

type RenewalRequest struct {
	CertPEM     []byte
	KeyPEM      []byte
	IssuerCAPEM []byte
}

type IdentityCertificate struct {
	Certificate *x509.Certificate
	CertPEM     []byte
	ChainPEM    []byte
	NotBefore   time.Time
	NotAfter    time.Time
}

type IdentityEnroller interface {
	Enroll(ctx context.Context, req EnrollmentRequest) (*IdentityCertificate, error)
}

type IdentityRenewer interface {
	Renew(ctx context.Context, req RenewalRequest) (*IdentityCertificate, error)
}

type IdentityCA interface {
	IdentityEnroller
	IdentityRenewer
}

