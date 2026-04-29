package policy

import "time"

type PolicyConfig struct {
	Profiles map[string]PolicyProfile `yaml:"profiles"`
	Hosts    map[string]PolicyHost    `yaml:"hosts"`
}

type PolicyProfile struct {
	CertType      string        `yaml:"cert_type"`
	DNSNames      []string      `yaml:"dns_names"`
	ACMEChallenge string        `yaml:"acme_challenge"`
	TTL           time.Duration `yaml:"ttl"`
	RenewBefore   time.Duration `yaml:"renew_before"`
}

type PolicyHost struct {
	Identity string   `yaml:"identity"`
	Profiles []string `yaml:"profiles"`
}
