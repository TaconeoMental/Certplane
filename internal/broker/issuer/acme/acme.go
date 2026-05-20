package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	lego "github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/httpreq"
	"github.com/go-acme/lego/v4/registration"

	"github.com/TaconeoMental/certplane/internal/broker/issuer"
	"github.com/TaconeoMental/certplane/internal/fileutil"
	"github.com/TaconeoMental/certplane/internal/pki"
	"github.com/TaconeoMental/certplane/internal/secrets"
)

type Config struct {
	DirectoryURL   string
	AccountEmail   string
	AccountKey     string
	DNSProvider    string
	PreferredChain string
	HTTPReq        HTTPReqConfig
}

type HTTPReqConfig struct {
	Endpoint             string
	Mode                 string
	UsernameSecret       string
	PasswordSecret       string
	PropagationTimeout   time.Duration
	PollingInterval      time.Duration
	HTTPTimeout          time.Duration
	RecursiveNameservers []string
}

type Issuer struct {
	cfg     Config
	secrets secrets.Provider
	user    *accountUser
}

type accountUser struct {
	email        string
	registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *accountUser) GetEmail() string                        { return u.email }
func (u *accountUser) GetRegistration() *registration.Resource { return u.registration }
func (u *accountUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

func New(cfg Config, secretProvider secrets.Provider) (*Issuer, error) {
	if cfg.DirectoryURL == "" {
		return nil, fmt.Errorf("acme directory URL is required")
	}
	if cfg.AccountEmail == "" {
		return nil, fmt.Errorf("acme account email is required")
	}
	if cfg.AccountKey == "" {
		return nil, fmt.Errorf("acme account key path is required")
	}
	if cfg.DNSProvider == "" {
		cfg.DNSProvider = "cloudflare"
	}

	key, err := loadOrCreateAccountKey(cfg.AccountKey)
	if err != nil {
		return nil, err
	}

	i := &Issuer{
		cfg:     cfg,
		secrets: secretProvider,
		user:    &accountUser{email: cfg.AccountEmail, key: key},
	}

	client, err := i.newClient()
	if err != nil {
		return nil, err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, fmt.Errorf("registering ACME account: %w", err)
	}
	i.user.registration = reg

	return i, nil
}

func (i *Issuer) Name() string      { return "acme" }
func (i *Issuer) Directory() string { return i.cfg.DirectoryURL }
func (i *Issuer) AccountKeyID() string {
	if i.user != nil && i.user.registration != nil && i.user.registration.URI != "" {
		return i.user.registration.URI
	}
	return i.cfg.AccountEmail
}

func (i *Issuer) Issue(ctx context.Context, req issuer.IssueRequest) (*pki.Bundle, error) {
	if req.ACMEChallenge != "dns-01" {
		return nil, fmt.Errorf("unsupported ACME challenge %q", req.ACMEChallenge)
	}

	client, err := i.newClient()
	if err != nil {
		return nil, err
	}
	if err := i.configureDNSProvider(ctx, client, req); err != nil {
		return nil, err
	}

	csr, err := pki.ParseCSRPEM(req.CSRPEM)
	if err != nil {
		return nil, fmt.Errorf("parsing CSR for ACME issuance: %w", err)
	}

	resource, err := client.Certificate.ObtainForCSR(certificate.ObtainForCSRRequest{
		CSR:            csr,
		Bundle:         false,
		PreferredChain: i.cfg.PreferredChain,
	})
	if err != nil {
		return nil, fmt.Errorf("obtaining ACME certificate for profile %q: %w", req.ProfileName, err)
	}
	if resource == nil || len(resource.Certificate) == 0 {
		return nil, fmt.Errorf("ACME returned empty certificate resource")
	}

	cert, err := pki.ParseCertificatePEM(resource.Certificate)
	if err != nil {
		return nil, fmt.Errorf("parsing ACME certificate: %w", err)
	}

	chainPEM := resource.IssuerCertificate
	fullchain := append([]byte{}, resource.Certificate...)
	fullchain = append(fullchain, chainPEM...)

	return &pki.Bundle{
		CertPEM:          resource.Certificate,
		ChainPEM:         chainPEM,
		FullChainPEM:     fullchain,
		LeafSerialNumber: pki.SerialString(cert.SerialNumber),
		NotBefore:        cert.NotBefore,
		NotAfter:         cert.NotAfter,
	}, nil
}

func (i *Issuer) newClient() (*lego.Client, error) {
	legoCfg := lego.NewConfig(i.user)
	legoCfg.CADirURL = i.cfg.DirectoryURL
	legoCfg.Certificate.KeyType = certcrypto.EC256

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, fmt.Errorf("creating lego ACME client: %w", err)
	}
	return client, nil
}

func (i *Issuer) configureDNSProvider(ctx context.Context, client *lego.Client, req issuer.IssueRequest) error {
	switch strings.ToLower(i.cfg.DNSProvider) {
	case "cloudflare":
		if i.secrets == nil {
			return fmt.Errorf("secrets provider is required for cloudflare dns-01")
		}
		if req.ACMECredentialsName == "" {
			return fmt.Errorf("cloudflare dns-01 requires an ACME credentials secret name")
		}

		token, err := i.secrets.Get(ctx, req.ACMECredentialsName)
		if err != nil {
			return fmt.Errorf("resolving cloudflare token secret %q: %w", req.ACMECredentialsName, err)
		}

		cloudflareConfig := cloudflare.NewDefaultConfig()
		cloudflareConfig.AuthToken = token

		provider, err := cloudflare.NewDNSProviderConfig(cloudflareConfig)
		if err != nil {
			return fmt.Errorf("creating cloudflare DNS provider: %w", err)
		}
		return client.Challenge.SetDNS01Provider(provider)

	case "httpreq":
		provider, err := i.httpreqProvider(ctx)
		if err != nil {
			return err
		}
		opts := []dns01.ChallengeOption{}
		if len(i.cfg.HTTPReq.RecursiveNameservers) > 0 {
			// lego's default propagation looks for the authoritative NS via
			// SOA queries. Servers like pebble-challtestsrv (which I use in
			// lab enviroments) return NOTIMP for SOA, breaking that process.
			// When the operator provides explicit nameservers, we bypass the
			// authoritative lookup and check TXT propagation directly at those
			// servers.
			opts = append(opts,
				dns01.AddRecursiveNameservers(i.cfg.HTTPReq.RecursiveNameservers),
				dns01.RecursiveNSsPropagationRequirement(),
				dns01.DisableAuthoritativeNssPropagationRequirement(),
			)
		}
		return client.Challenge.SetDNS01Provider(provider, opts...)

	default:
		return fmt.Errorf("unsupported ACME DNS provider %q", i.cfg.DNSProvider)
	}
}

func (i *Issuer) httpreqProvider(ctx context.Context) (*httpreq.DNSProvider, error) {
	endpoint, err := url.Parse(i.cfg.HTTPReq.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing httpreq endpoint %q: %w", i.cfg.HTTPReq.Endpoint, err)
	}

	cfg := httpreq.NewDefaultConfig()
	cfg.Endpoint = endpoint
	cfg.Mode = i.cfg.HTTPReq.Mode
	cfg.PropagationTimeout = i.cfg.HTTPReq.PropagationTimeout
	cfg.PollingInterval = i.cfg.HTTPReq.PollingInterval
	cfg.HTTPClient = &http.Client{Timeout: i.cfg.HTTPReq.HTTPTimeout}

	if i.cfg.HTTPReq.UsernameSecret != "" {
		if i.secrets == nil {
			return nil, fmt.Errorf("secrets provider is required for httpreq username")
		}
		username, err := i.secrets.Get(ctx, i.cfg.HTTPReq.UsernameSecret)
		if err != nil {
			return nil, fmt.Errorf("resolving httpreq username secret %q: %w", i.cfg.HTTPReq.UsernameSecret, err)
		}
		cfg.Username = username
	}

	if i.cfg.HTTPReq.PasswordSecret != "" {
		if i.secrets == nil {
			return nil, fmt.Errorf("secrets provider is required for httpreq password")
		}
		password, err := i.secrets.Get(ctx, i.cfg.HTTPReq.PasswordSecret)
		if err != nil {
			return nil, fmt.Errorf("resolving httpreq password secret %q: %w", i.cfg.HTTPReq.PasswordSecret, err)
		}
		cfg.Password = password
	}

	provider, err := httpreq.NewDNSProviderConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating httpreq DNS provider: %w", err)
	}
	return provider, nil
}

func loadOrCreateAccountKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return parseAccountKey(path, data)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("reading ACME account key %q: %w", path, err)
	}
	return createAccountKey(path)
}

func parseAccountKey(path string, data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("ACME account key %q is not PEM", path)
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("parsing ACME account key %q: unsupported key format", path)
}

func createAccountKey(path string) (crypto.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ACME account key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling ACME account key: %w", err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := fileutil.WriteFileAtomic(path, pemData, 0o600); err != nil {
		return nil, fmt.Errorf("writing ACME account key %q: %w", path, err)
	}
	return key, nil
}
