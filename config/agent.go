package config

import "time"

type AgentConfig struct {
	Identity     AgentIdentityConfig `yaml:"identity"`
	Broker       AgentBrokerConfig   `yaml:"broker"`
	StateDir     string              `yaml:"state_dir"`
	Certificates []CertConfig        `yaml:"certificates"`
	Logging      LoggingConfig       `yaml:"logging"`
}

type AgentIdentityConfig struct {
	CN            string        `yaml:"cn"`
	CAURL         string        `yaml:"ca_url"`
	CAFingerprint string        `yaml:"ca_fingerprint"`
	Cert          string        `yaml:"cert"`
	Key           string        `yaml:"key"`
	BoostrapToken string        `yaml:"bootstrap_token"`
	RenewBefore   time.Duration `yaml:"renew_before"`
}

type AgentBrokerConfig struct {
	URL      string        `yaml:"url"`
	ServerCA string        `yaml:"server_ca"`
	Timeout  time.Duration `yaml:"timeout"`
	Retries  int           `yaml:"retries"`
}

type CertConfig struct {
	Profile       string        `yaml:"profile"`
	Key           string        `yaml:"key"`
	Cert          string        `yaml:"cert"`
	Chain         string        `yaml:"chain"`
	FullChain     string        `yaml:"fullchain"`
	ReloadCommand string        `yaml:"reload_command"`
	RenewBefore   time.Duration `yaml:"renew_before"`
}
