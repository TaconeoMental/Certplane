package config

import "time"

type BrokerConfig struct {
	Server     BrokerServerConfig `yaml:"server"`
	Policy     BrokerPolicyConfig `yaml:"policy"`
	IdentityCA IdentityCAConfig   `yaml:"identity_ca"`
	PublicCA   PublicCAConfig     `yaml:"public_ca"`
	State      StateConfig        `yaml:"state"`
	Logging    LoggingConfig      `yaml:"logging"`
}

type BrokerServerConfig struct {
	Address string    `yaml:"address"`
	TLS     ServerTLS `yaml:"tls"`
}

type ServerTLS struct {
	Cert       string `yaml:"cert"`
	Key        string `yaml:"key"`
	ClientCA   string `yaml:"client_ca"`
	MinVersion string `yaml:"min_version"`
}

type BrokerPolicyConfig struct {
	Path  string `yaml:"path"`
	Watch bool   `yaml:"watch"`
}

type IdentityCAConfig struct {
	Provider string       `yaml:"provider"`
	StepCA   StepCAConfig `yaml:"step_ca"`
}

type StepCAConfig struct {
	URL         string        `yaml:"url"`
	Fingerprint string        `yaml:"fingerprint"`
	RootCA      string        `yaml:"root_ca"`
	Timeout     time.Duration `yaml:"timeout"`
}

type PublicCAConfig struct {
	Provider    string            `yaml:"provider"`
	LetsEncrypt LetsEncryptConfig `yaml:"letsencrypt"`
}

type LetsEncryptConfig struct {
	Email       string        `yaml:"email"`
	Directory   string        `yaml:"directory"`
	DNS         DNSConfig     `yaml:"dns"`
	DataDir     string        `yaml:"data_dir"`
	RenewBefore time.Duration `yaml:"renew_before"`
}

type DNSConfig struct {
	Provider           string        `yaml:"provider"`
	CredentialsFile    string        `yaml:"credentials_file"`
	PropagationTimeout time.Duration `yaml:"propagation_timeout"`
	PollingInterval    time.Duration `yaml:"polling_interval"`
}

type StateConfig struct {
	Path string `yaml:"path"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}
