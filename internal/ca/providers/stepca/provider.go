package stepca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"time"

	"github.com/TaconeoMental/certplane/internal/ca"
	"github.com/TaconeoMental/certplane/internal/pki"
	"github.com/smallstep/certificates/api"
	stepclient "github.com/smallstep/certificates/ca"
)

type Config struct {
	URL         string
	Fingerprint string
	RootCAPath  string
	Timeout     time.Duration
}

type Provider struct {
	cfg Config
}

func New(cfg Config) (*Provider, error) {
	// TODO: validar acá los campos del struct? defaults??? ya veremos...
	return &Provider{cfg: cfg}, nil
}

// obtains the first identity certificate using a one time JWT token issued by
// the step-ca JWK provisionesr
func (p *Provider) Enroll(ctx context.Context, req *ca.EnrollmentRequest) (*ca.IdentityCertificate, error) {
	if req.Token == "" {
		return nil, fmt.Errorf("bootstrap token is required for enrollment")
	}

	client, err := stepclient.NewClient(p.cfg.URL,
		stepclient.WithRootSHA256(p.cfg.Fingerprint),
		stepclient.WithTimeout(p.cfg.Timeout),
	)
	if err != nil {
		return nil, fmt.Errorf("creating step-ca client: %w", err)
	}

	resp, err := client.SignWithContext(ctx, &api.SignRequest{
		CsrPEM: api.NewCertificateRequest(req.CSR),
		OTT:    req.Token,
	})
	if err != nil {
		return nil, fmt.Errorf("signing certificate with step-ca: %w", err)
	}

	cert := resp.CertChainPEM[0].Certificate
	return &ca.IdentityCertificate{
		Certificate: cert,
		CertPEM:     pki.EncodeCertPEM(cert),
	}, nil
}

func (p *Provider) Renew(ctx context.Context, certPEM []byte, keyPEM []byte, rootCAPEM []byte) (*ca.IdentityCertificate, error) {
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(rootCAPEM) {
		return nil, fmt.Errorf("parsing root CA certificate")
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading identity keypair: %w", err)
	}

	// unlike Enroll() we now already have an identity certificate, so we need
	// to create our own transport to auth our identity during the mTLS
	// handhsake
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			RootCAs:      rootPool,
			MinVersion:   tls.VersionTLS12,
		},
	}

	client, err := stepclient.NewClient(p.cfg.URL,
		stepclient.WithTransport(transport),
		stepclient.WithTimeout(p.cfg.Timeout),
	)
	if err != nil {
		return nil, fmt.Errorf("creating renewal client: %w", err)
	}

	resp, err := client.RenewWithContext(ctx, transport)
	if err != nil {
		return nil, fmt.Errorf("renewing certificate with step-ca: %w", err)
	}

	cert := resp.CertChainPEM[0].Certificate
	return &ca.IdentityCertificate{
		Certificate: cert,
		CertPEM:     pki.EncodeCertPEM(cert),
	}, nil
}

func (p *Provider) Revoke(ctx context.Context, serial string) error {
	client, err := stepclient.NewClient(p.cfg.URL,
		stepclient.WithRootSHA256(p.cfg.Fingerprint),
		stepclient.WithTimeout(p.cfg.Timeout),
	)
	if err != nil {
		return fmt.Errorf("creating step-ca client: %w", err)
	}

	_, err = client.RevokeWithContext(ctx, &api.RevokeRequest{
		Serial:     serial,
		ReasonCode: 0,
		Reason:     "revoked by certplane",
	}, nil)
	if err != nil {
		return fmt.Errorf("revoking certificate %s: %w", serial, err)
	}
	return nil
}

// verificamos interfaz en compile time ;)
var _ ca.IdentityCA = (*Provider)(nil)
