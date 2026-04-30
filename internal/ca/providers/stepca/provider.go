package stepca

import (
	"context"
	"errors"

	"github.com/TaconeoMental/certplane/ca"
)

type Config struct {
	URL         string
	Fingerprint string
}

type Provider struct {
	cfg Config
}

func New(cfg Config) (*Provider, error) {
	// TODO: validar acá los campos del struct?
	return &Provider{cfg: cfg}, nil
}

func (p *Provider) Enroll(ctx context.Context, req *ca.EnrollmentRequest) (*ca.IdentityCertificate, error) {
	return nil, errors.New("not implementesd")
}

func (p *Provider) Renew(ctx context.Context, certPEM []byte) (*ca.IdentityCertificate, error) {
	return nil, errors.New("not implemented")
}

func (p *Provider) Revoke(ctx context.Context, serial string) error {
	return errors.New("not implemented")
}
