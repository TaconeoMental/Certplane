package config

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

type BrokerConfig struct {
	Server     BrokerServerConfig `yaml:"server"`
	Policy     BrokerPolicyConfig `yaml:"policy"`
	Issuer     IssuerConfig       `yaml:"issuer"`
	Secrets    SecretsConfig      `yaml:"secrets"`
	Store      StoreConfig        `yaml:"store"`
	Audit      AuditConfig        `yaml:"audit"`
	RateLimits RateLimitsConfig   `yaml:"rate_limits"`
	Logging    LoggingConfig      `yaml:"logging"`
}

type BrokerServerConfig struct {
	Address           string           `yaml:"address"`
	TLS               ServerTLSConfig  `yaml:"tls"`
	MTLS              ServerMTLSConfig `yaml:"mtls"`
	ReadHeaderTimeout time.Duration    `yaml:"read_header_timeout"`
	ReadTimeout       time.Duration    `yaml:"read_timeout"`
	WriteTimeout      time.Duration    `yaml:"write_timeout"`
	IdleTimeout       time.Duration    `yaml:"idle_timeout"`
}

type ServerTLSConfig struct {
	Cert       string `yaml:"cert"`
	Key        string `yaml:"key"`
	MinVersion string `yaml:"min_version"`
}

type ServerMTLSConfig struct {
	AgentCABundle string `yaml:"agent_ca_bundle"`
}

type BrokerPolicyConfig struct {
	Path  string `yaml:"path"`
	Watch bool   `yaml:"watch"`
}

type IssuerConfig struct {
	Provider string     `yaml:"provider"`
	ACME     ACMEConfig `yaml:"acme"`
}

type ACMEConfig struct {
	DirectoryURL   string            `yaml:"directory_url"`
	AccountEmail   string            `yaml:"account_email"`
	AccountKey     string            `yaml:"account_key"`
	DNSProvider    string            `yaml:"dns_provider"`
	PreferredChain string            `yaml:"preferred_chain"`
	HTTPReq        HTTPReqACMEConfig `yaml:"httpreq"`
}

type HTTPReqACMEConfig struct {
	Endpoint           string        `yaml:"endpoint"`
	Mode               string        `yaml:"mode"`
	UsernameSecret     string        `yaml:"username_secret"`
	PasswordSecret     string        `yaml:"password_secret"`
	PropagationTimeout time.Duration `yaml:"propagation_timeout"`
	PollingInterval    time.Duration `yaml:"polling_interval"`
	HTTPTimeout        time.Duration `yaml:"http_timeout"`
}

type SecretsConfig struct {
	Provider string      `yaml:"provider"`
	Vault    VaultConfig `yaml:"vault"`
}

type VaultConfig struct {
	Address   string        `yaml:"address"`
	Token     string        `yaml:"token"`
	TokenFile string        `yaml:"token_file"`
	MountPath string        `yaml:"mount_path"`
	KVVersion int           `yaml:"kv_version"`
	Key       string        `yaml:"key"`
	Timeout   time.Duration `yaml:"timeout"`
	Namespace string        `yaml:"namespace"`
}

type StoreConfig struct {
	Driver string `yaml:"driver"`
	Path   string `yaml:"path"`
}

type AuditConfig struct {
	Enabled     *bool  `yaml:"enabled"`
	FailureMode string `yaml:"failure_mode"` // fail_open | fail_closed
	MirrorToLog bool   `yaml:"mirror_to_log"`
}

type RateLimitsConfig struct {
	PerIdentityPerHour        int `yaml:"per_identity_per_hour"`
	PerIdentityProfilePerHour int `yaml:"per_identity_profile_per_hour"`
}

func (c *BrokerConfig) ApplyDefaults() {
	if c.Server.Address == "" {
		c.Server.Address = ":8443"
	}
	if c.Server.ReadHeaderTimeout == 0 {
		c.Server.ReadHeaderTimeout = 5 * time.Second
	}
	if c.Server.ReadTimeout == 0 {
		c.Server.ReadTimeout = 10 * time.Second
	}
	if c.Server.WriteTimeout == 0 {
		c.Server.WriteTimeout = 60 * time.Second
	}
	if c.Server.IdleTimeout == 0 {
		c.Server.IdleTimeout = 120 * time.Second
	}
	if c.Server.TLS.MinVersion == "" {
		c.Server.TLS.MinVersion = "1.2"
	}
	if c.Store.Driver == "" {
		c.Store.Driver = "sqlite"
	}
	if c.Store.Path == "" {
		c.Store.Path = "/var/lib/certplane/broker.db"
	}
	if c.Audit.FailureMode == "" {
		c.Audit.FailureMode = "fail_open"
	}
	if c.Issuer.Provider == "" {
		c.Issuer.Provider = "acme"
	}
	if c.Issuer.ACME.HTTPReq.PropagationTimeout == 0 {
		c.Issuer.ACME.HTTPReq.PropagationTimeout = 30 * time.Second
	}
	if c.Issuer.ACME.HTTPReq.PollingInterval == 0 {
		c.Issuer.ACME.HTTPReq.PollingInterval = 2 * time.Second
	}
	if c.Issuer.ACME.HTTPReq.HTTPTimeout == 0 {
		c.Issuer.ACME.HTTPReq.HTTPTimeout = 10 * time.Second
	}
	if c.RateLimits.PerIdentityPerHour == 0 {
		c.RateLimits.PerIdentityPerHour = 50
	}
	if c.RateLimits.PerIdentityProfilePerHour == 0 {
		c.RateLimits.PerIdentityProfilePerHour = 20
	}
	if c.Secrets.Provider == "" {
		c.Secrets.Provider = "env"
	}
	if c.Secrets.Vault.MountPath == "" {
		c.Secrets.Vault.MountPath = "secret"
	}
	if c.Secrets.Vault.KVVersion == 0 {
		c.Secrets.Vault.KVVersion = 2
	}
	if c.Secrets.Vault.Key == "" {
		c.Secrets.Vault.Key = "value"
	}
	if c.Secrets.Vault.Timeout == 0 {
		c.Secrets.Vault.Timeout = 10 * time.Second
	}
	c.Logging.ApplyDefaults("info", "json", "stdout")
}

func (c *BrokerConfig) AuditEnabled() bool {
	if c.Audit.Enabled == nil {
		return true
	}
	return *c.Audit.Enabled
}

func (c *BrokerConfig) Validate() error {
	var errs []error
	if c.Server.TLS.Cert == "" {
		errs = append(errs, fmt.Errorf("server.tls.cert is required"))
	}
	if c.Server.TLS.Key == "" {
		errs = append(errs, fmt.Errorf("server.tls.key is required"))
	}
	if c.Server.MTLS.AgentCABundle == "" {
		errs = append(errs, fmt.Errorf("server.mtls.agent_ca_bundle is required"))
	}
	switch c.Server.TLS.MinVersion {
	case "1.2", "1.3":
	default:
		errs = append(errs, fmt.Errorf("server.tls.min_version must be 1.2 or 1.3"))
	}
	if c.Server.ReadHeaderTimeout <= 0 || c.Server.ReadTimeout <= 0 || c.Server.WriteTimeout <= 0 || c.Server.IdleTimeout <= 0 {
		errs = append(errs, fmt.Errorf("server timeouts must be positive"))
	}
	if c.Policy.Path == "" {
		errs = append(errs, fmt.Errorf("policy.path is required"))
	}
	switch c.Issuer.Provider {
	case "acme":
		if c.Issuer.ACME.DirectoryURL == "" {
			errs = append(errs, fmt.Errorf("issuer.acme.directory_url is required for acme issuer"))
		} else if _, err := url.ParseRequestURI(c.Issuer.ACME.DirectoryURL); err != nil {
			errs = append(errs, fmt.Errorf("issuer.acme.directory_url is invalid: %w", err))
		}
		if c.Issuer.ACME.AccountEmail == "" {
			errs = append(errs, fmt.Errorf("issuer.acme.account_email is required for acme issuer"))
		}
		if c.Issuer.ACME.AccountKey == "" {
			errs = append(errs, fmt.Errorf("issuer.acme.account_key is required for acme issuer"))
		}
		if c.Issuer.ACME.DNSProvider == "" {
			errs = append(errs, fmt.Errorf("issuer.acme.dns_provider is required for acme issuer"))
		}
		switch c.Issuer.ACME.DNSProvider {
		case "cloudflare":
		case "httpreq":
			if c.Issuer.ACME.HTTPReq.Endpoint == "" {
				errs = append(errs, fmt.Errorf("issuer.acme.httpreq.endpoint is required when dns_provider is httpreq"))
			} else if _, err := url.ParseRequestURI(c.Issuer.ACME.HTTPReq.Endpoint); err != nil {
				errs = append(errs, fmt.Errorf("issuer.acme.httpreq.endpoint is invalid: %w", err))
			}
			if c.Issuer.ACME.HTTPReq.Mode != "" && c.Issuer.ACME.HTTPReq.Mode != "RAW" {
				errs = append(errs, fmt.Errorf("issuer.acme.httpreq.mode must be empty or RAW"))
			}
			if c.Issuer.ACME.HTTPReq.PropagationTimeout <= 0 || c.Issuer.ACME.HTTPReq.PollingInterval <= 0 || c.Issuer.ACME.HTTPReq.HTTPTimeout <= 0 {
				errs = append(errs, fmt.Errorf("issuer.acme.httpreq timeouts must be positive"))
			}
		default:
			errs = append(errs, fmt.Errorf("issuer.acme.dns_provider must be cloudflare or httpreq"))
		}
	default:
		errs = append(errs, fmt.Errorf("issuer.provider must be acme"))
	}
	switch c.Secrets.Provider {
	case "env", "file":
	case "vault", "openbao":
		if c.Secrets.Vault.Address == "" {
			errs = append(errs, fmt.Errorf("secrets.vault.address is required when secrets.provider is vault/openbao"))
		}
		switch c.Secrets.Vault.KVVersion {
		case 1, 2:
		default:
			errs = append(errs, fmt.Errorf("secrets.vault.kv_version must be 1 or 2"))
		}
	default:
		errs = append(errs, fmt.Errorf("secrets.provider must be env, file, vault or openbao"))
	}
	switch c.Store.Driver {
	case "sqlite", "file":
		if c.Store.Path == "" {
			errs = append(errs, fmt.Errorf("store.path is required"))
		}
	default:
		errs = append(errs, fmt.Errorf("store.driver must be sqlite or file"))
	}
	switch c.Audit.FailureMode {
	case "fail_open", "fail_closed":
	default:
		errs = append(errs, fmt.Errorf("audit.failure_mode must be fail_open or fail_closed"))
	}
	if c.RateLimits.PerIdentityPerHour < 0 {
		errs = append(errs, fmt.Errorf("rate_limits.per_identity_per_hour cannot be negative"))
	}
	if c.RateLimits.PerIdentityProfilePerHour < 0 {
		errs = append(errs, fmt.Errorf("rate_limits.per_identity_profile_per_hour cannot be negative"))
	}
	if err := c.Logging.Validate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
