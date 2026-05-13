package policy

import (
	"errors"
	"time"
)

const CurrentVersion = 1

var (
	ErrUnknownIdentity   = errors.New("unknown identity")
	ErrUnknownProfile    = errors.New("unknown profile")
	ErrProfileNotAllowed = errors.New("profile not allowed")
	ErrCSRNamesMismatch  = errors.New("csr dns names do not match profile")
)

type Config struct {
	// Implementing versioning here because, knowing my track record, this will
	// change again :)
	Version  int                `yaml:"version"`
	Profiles map[string]Profile `yaml:"profiles"`
	Hosts    map[string]Host    `yaml:"hosts"`
}

type Profile struct {
	Type        string        `yaml:"type"`
	DNSNames    []string      `yaml:"dns_names"`
	ACME        ACMEProfile   `yaml:"acme"`
	RenewBefore time.Duration `yaml:"renew_before"`
}

type ACMEProfile struct {
	Challenge   string `yaml:"challenge"`
	Credentials string `yaml:"credentials"`
}

type Host struct {
	Identity string   `yaml:"identity"`
	Profiles []string `yaml:"profiles"`
}

type CompiledPolicy struct {
	Version         int
	Profiles        map[string]CompiledProfile
	HostsByName     map[string]CompiledHost
	HostsByIdentity map[string]CompiledHost
	Hash            string
	LoadedAt        time.Time
}

type CompiledProfile struct {
	Name        string
	Type        string
	DNSNames    []string
	ACME        CompiledACMEProfile
	RenewBefore time.Duration
	Hash        string
}

type CompiledACMEProfile struct {
	Challenge   string `json:"challenge"`
	Credentials string `json:"credentials"`
}

type CompiledHost struct {
	Name     string
	Identity string
	Profiles map[string]bool
}

func (h CompiledHost) AllowsProfile(name string) bool {
	return h.Profiles[name]
}
