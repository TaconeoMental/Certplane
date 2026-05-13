package policy

import "time"

type Config struct {
	Version  int                `json:"version" yaml:"version"`
	Profiles map[string]Profile `json:"profiles" yaml:"profiles"`
	Hosts    map[string]Host    `json:"hosts" yaml:"hosts"`
}

type Profile struct {
	Type        string            `json:"type" yaml:"type"`
	DNSNames    []string          `json:"dns_names" yaml:"dns_names"`
	ACME        ACMEProfile       `json:"acme" yaml:"acme"`
	RenewBefore duration.Duration `json:"renew_before" yaml:"renew_before"`
}

type ACMEProfile struct {
	Challenge   string `json:"challenge" yaml:"challenge"`
	Credentials string `json:"credentials" yaml:"credentials"`
}

type Host struct {
	Identity string   `json:"identity" yaml:"identity"`
	Profiles []string `json:"profiles" yaml:"profiles"`
}

