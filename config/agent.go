package config

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"github.com/TaconeoMental/certplane/internal/dnsname"
)

type AgentConfig struct {
	StateDir     string              `yaml:"state_dir"`
	Identity     AgentIdentityConfig `yaml:"identity"`
	Broker       AgentBrokerConfig   `yaml:"broker"`
	Certificates []CertConfig        `yaml:"certificates"`
	Audit        AgentAuditConfig    `yaml:"audit"`
	Logging      LoggingConfig       `yaml:"logging"`
}

type AgentIdentityConfig struct {
	Name           string        `yaml:"name"`
	Provider       string        `yaml:"provider"`
	Cert           string        `yaml:"cert"`
	Key            string        `yaml:"key"`
	IssuerCABundle string        `yaml:"issuer_ca_bundle"`
	BootstrapToken string        `yaml:"bootstrap_token"`
	RenewBefore    time.Duration `yaml:"renew_before"`
	WarnBefore     time.Duration `yaml:"warn_before"`
	StepCA         StepCAConfig  `yaml:"step_ca"`
}

type StepCAConfig struct {
	URL          string        `yaml:"url"`
	Fingerprint  string        `yaml:"fingerprint"`
	RootCABundle string        `yaml:"root_ca_bundle"`
	Timeout      time.Duration `yaml:"timeout"`
}

type AgentBrokerConfig struct {
	URL            string        `yaml:"url"`
	ServerCABundle string        `yaml:"server_ca_bundle"`
	Timeout        time.Duration `yaml:"timeout"`
}

type CertConfig struct {
	Name          string        `yaml:"name"`
	Profile       string        `yaml:"profile"`
	DNSNames      []string      `yaml:"dns_names"`
	Key           string        `yaml:"key"`
	Cert          string        `yaml:"cert"`
	Chain         string        `yaml:"chain"`
	FullChain     string        `yaml:"fullchain"`
	ReloadCommand string        `yaml:"reload_command"`
	ReloadTimeout time.Duration `yaml:"reload_timeout"`
	RenewBefore   time.Duration `yaml:"renew_before"`
}

type AgentAuditConfig struct {
	Enabled      *bool         `yaml:"enabled"`
	Mode         string        `yaml:"mode"` // off | stdout | broker | both
	SpoolDir     string        `yaml:"spool_dir"`
	FlushTimeout time.Duration `yaml:"flush_timeout"`
	MaxBatchSize int           `yaml:"max_batch_size"`
}

func (c *AgentConfig) ApplyDefaults() {
	if c.StateDir == "" {
		c.StateDir = "/var/lib/certplane/agent"
	}
	if c.Identity.Provider == "" {
		c.Identity.Provider = "step-ca"
	}
	if c.Identity.RenewBefore == 0 {
		c.Identity.RenewBefore = 8 * time.Hour
	}
	if c.Identity.WarnBefore == 0 {
		c.Identity.WarnBefore = 24 * time.Hour
	}
	if c.Identity.StepCA.Timeout == 0 {
		c.Identity.StepCA.Timeout = 10 * time.Second
	}
	if c.Broker.Timeout == 0 {
		c.Broker.Timeout = 30 * time.Second
	}
	for i := range c.Certificates {
		if c.Certificates[i].RenewBefore == 0 {
			c.Certificates[i].RenewBefore = 30 * 24 * time.Hour
		}
		if c.Certificates[i].ReloadTimeout == 0 {
			c.Certificates[i].ReloadTimeout = 30 * time.Second
		}
	}
	if c.Audit.Mode == "" {
		c.Audit.Mode = "broker"
	}
	if c.Audit.SpoolDir == "" {
		c.Audit.SpoolDir = filepath.Join(c.StateDir, "events")
	}
	if c.Audit.FlushTimeout == 0 {
		c.Audit.FlushTimeout = 10 * time.Second
	}
	if c.Audit.MaxBatchSize == 0 {
		c.Audit.MaxBatchSize = 100
	}
	c.Logging.ApplyDefaults("info", "text", "stderr")
}

func (c *AgentConfig) AuditEnabled() bool {
	if c.Audit.Enabled == nil {
		return c.Audit.Mode != "off"
	}
	return *c.Audit.Enabled && c.Audit.Mode != "off"
}

func (c *AgentConfig) Validate() error {
	var errs []error
	if c.Identity.Name == "" {
		errs = append(errs, fmt.Errorf("identity.name is required"))
	}
	if c.Identity.Cert == "" || c.Identity.Key == "" {
		errs = append(errs, fmt.Errorf("identity.cert and identity.key are required"))
	}
	if c.Identity.IssuerCABundle == "" {
		errs = append(errs, fmt.Errorf("identity.issuer_ca_bundle is required"))
	}
	if c.Identity.RenewBefore <= 0 {
		errs = append(errs, fmt.Errorf("identity.renew_before must be positive"))
	}
	if c.Identity.WarnBefore <= 0 {
		errs = append(errs, fmt.Errorf("identity.warn_before must be positive"))
	}
	switch c.Identity.Provider {
	case "step-ca":
		if c.Identity.StepCA.URL == "" {
			errs = append(errs, fmt.Errorf("identity.step_ca.url is required for step-ca provider"))
		}
		if _, err := url.ParseRequestURI(c.Identity.StepCA.URL); err != nil {
			errs = append(errs, fmt.Errorf("identity.step_ca.url must be a valid URL: %w", err))
		}
		if c.Identity.StepCA.Fingerprint == "" && c.Identity.StepCA.RootCABundle == "" {
			errs = append(errs, fmt.Errorf("identity.step_ca.fingerprint or identity.step_ca.root_ca_bundle is required for step-ca provider"))
		}
	default:
		errs = append(errs, fmt.Errorf("identity.provider must be step-ca"))
	}
	if c.Broker.URL == "" {
		errs = append(errs, fmt.Errorf("broker.url is required"))
	} else if _, err := url.ParseRequestURI(c.Broker.URL); err != nil {
		errs = append(errs, fmt.Errorf("broker.url must be a valid URL: %w", err))
	}
	if c.Broker.ServerCABundle == "" {
		errs = append(errs, fmt.Errorf("broker.server_ca_bundle is required"))
	}
	if c.Broker.Timeout <= 0 {
		errs = append(errs, fmt.Errorf("broker.timeout must be positive"))
	}
	if len(c.Certificates) == 0 {
		errs = append(errs, fmt.Errorf("at least one certificate entry is required"))
	}
	seen := map[string]struct{}{}
	for i, cert := range c.Certificates {
		name := cert.Name
		if name == "" {
			name = fmt.Sprintf("index %d", i)
			errs = append(errs, fmt.Errorf("certificates[%d].name is required", i))
		}
		if _, ok := seen[cert.Name]; cert.Name != "" && ok {
			errs = append(errs, fmt.Errorf("duplicate certificate name %q", cert.Name))
		}
		if cert.Name != "" {
			seen[cert.Name] = struct{}{}
		}
		if cert.Profile == "" {
			errs = append(errs, fmt.Errorf("certificates[%s].profile is required", name))
		}
		if len(cert.DNSNames) == 0 {
			errs = append(errs, fmt.Errorf("certificates[%s].dns_names is required", name))
		} else if _, err := dnsname.CanonicalList(cert.DNSNames); err != nil {
			errs = append(errs, fmt.Errorf("certificates[%s].dns_names: %w", name, err))
		}
		if cert.Key == "" || cert.Cert == "" || cert.Chain == "" || cert.FullChain == "" {
			errs = append(errs, fmt.Errorf("certificates[%s] key/cert/chain/fullchain are required", name))
		}
		if cert.Key != "" && cert.Cert != "" && filepath.Clean(cert.Key) == filepath.Clean(cert.Cert) {
			errs = append(errs, fmt.Errorf("certificates[%s] key and cert paths must differ", name))
		}
		if cert.RenewBefore <= 0 {
			errs = append(errs, fmt.Errorf("certificates[%s].renew_before must be positive", name))
		}
		if cert.ReloadCommand != "" && cert.ReloadTimeout <= 0 {
			errs = append(errs, fmt.Errorf("certificates[%s].reload_timeout must be positive", name))
		}
	}
	switch c.Audit.Mode {
	case "off", "stdout", "broker", "both":
	default:
		errs = append(errs, fmt.Errorf("audit.mode must be off, stdout, broker or both"))
	}
	if c.Audit.MaxBatchSize < 0 {
		errs = append(errs, fmt.Errorf("audit.max_batch_size cannot be negative"))
	}
	if err := c.Logging.Validate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
