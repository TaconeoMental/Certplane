package stepca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	stepapi "github.com/smallstep/certificates/api"
	stepca "github.com/smallstep/certificates/ca"

	"github.com/TaconeoMental/certplane/internal/ca"
	"github.com/TaconeoMental/certplane/internal/pki"
)

type Config struct {
	URL         string
	Fingerprint string
	RootCAPath  string
	Timeout     time.Duration
}

type Provider struct {
	cfg    Config
	client *stepca.Client
}

func New(cfg Config) (*Provider, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("step-ca url is required")
	}
	if cfg.Fingerprint == "" && cfg.RootCAPath == "" {
		return nil, fmt.Errorf("step-ca fingerprint or root CA path is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	client, err := newClient(cfg)
	if err != nil {
		return nil, err
	}
	return &Provider{cfg: cfg, client: client}, nil
}

func (p *Provider) Enroll(ctx context.Context, req ca.EnrollmentRequest) (*ca.IdentityCertificate, error) {
	token := strings.TrimSpace(req.Token)
	if token == "" {
		return nil, fmt.Errorf("bootstrap token is empty")
	}
	csr, err := pki.ParseCSRPEM(req.CSRPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing identity CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid identity CSR signature: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, p.cfg.Timeout)
	defer cancel()

	resp, err := p.client.SignWithContext(ctx, &stepapi.SignRequest{
		CsrPEM: stepapi.NewCertificateRequest(csr),
		OTT: token,
	})
	if err != nil {
		return nil, fmt.Errorf("signing identity CSR with step-ca: %w", err)
	}
	return identityFromSignResponse(resp)
}

func (p *Provider) Renew(ctx context.Context, req ca.RenewalRequest) (*ca.IdentityCertificate, error) {
	if len(req.CertPEM) == 0 || len(req.KeyPEM) == 0 {
		return nil, fmt.Errorf("identity cert and key are required for renewal")
	}
	tlsCert, err := tls.X509KeyPair(req.CertPEM, req.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading identity TLS keypair: %w", err)
	}

	cfg := p.cfg
	client, err := newClientWithCertificate(cfg, tlsCert)
	if err != nil {
		return nil, err
	}
	defer client.CloseIdleConnections()

	resp, err := client.Renew(nil)
	if err != nil {
		return nil, fmt.Errorf("renewing identity certificate with step-ca: %w", err)
	}
	return identityFromSignResponse(resp)
}

func newClient(cfg Config) (*stepca.Client, error) {
	opts := []stepca.ClientOption{stepca.WithTimeout(cfg.Timeout)}
	if cfg.RootCAPath != "" {
		opts = append(opts, stepca.WithRootFile(cfg.RootCAPath))
	} else {
		opts = append(opts, stepca.WithRootSHA256(cfg.Fingerprint))
	}
	client, err := stepca.NewClient(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating step-ca client: %w", err)
	}
	return client, nil
}

func newClientWithCertificate(cfg Config, cert tls.Certificate) (*stepca.Client, error) {
	opts := []stepca.ClientOption{stepca.WithTimeout(cfg.Timeout), stepca.WithCertificate(cert)}
	if cfg.RootCAPath != "" {
		opts = append(opts, stepca.WithRootFile(cfg.RootCAPath))
	} else {
		opts = append(opts, stepca.WithRootSHA256(cfg.Fingerprint))
	}
	client, err := stepca.NewClient(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("creating step-ca renewal client: %w", err)
	}
	return client, nil
}

func identityFromSignResponse(resp *stepapi.SignResponse) (*ca.IdentityCertificate, error) {
	if resp == nil {
		return nil, fmt.Errorf("step-ca returned nil sign response")
	}
	cert := resp.ServerPEM.Certificate
	if cert == nil && len(resp.CertChainPEM) > 0 {
		cert = resp.CertChainPEM[0].Certificate
	}
	if cert == nil {
		return nil, fmt.Errorf("step-ca sign response contains no leaf certificate")
	}
	certPEM := certToPEM(cert)
	var chainPEM []byte
	if resp.CaPEM.Certificate != nil {
		chainPEM = append(chainPEM, certToPEM(resp.CaPEM.Certificate)...)
	}
	for _, c := range resp.CertChainPEM {
		if c.Certificate == nil || c.Certificate.Equal(cert) {
			continue
		}
		chainPEM = append(chainPEM, certToPEM(c.Certificate)...)
	}
	return &ca.IdentityCertificate{Certificate: cert, CertPEM: certPEM, ChainPEM: chainPEM, NotBefore: cert.NotBefore, NotAfter: cert.NotAfter}, nil
}

func certToPEM(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

var _ ca.IdentityCA = (*Provider)(nil)
