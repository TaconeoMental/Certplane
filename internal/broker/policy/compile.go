package policy

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/TaconeoMental/certplane/internal/dnsname"
)

const defaultRenewBefore = 30 * 24 * time.Hour

func Compile(cfg Config) (*CompiledPolicy, error) {
	if cfg.Version == 0 {
		cfg.Version = CurrentVersion
	}
	if cfg.Version != CurrentVersion {
		return nil, fmt.Errorf("unsupported policy version %d", cfg.Version)
	}
	if len(cfg.Profiles) == 0 {
		return nil, fmt.Errorf("policy must define at least one profile")
	}
	if len(cfg.Hosts) == 0 {
		return nil, fmt.Errorf("policy must define at least one host")
	}

	compiled := &CompiledPolicy{
		Version:         cfg.Version,
		Profiles:        make(map[string]CompiledProfile, len(cfg.Profiles)),
		HostsByName:     make(map[string]CompiledHost, len(cfg.Hosts)),
		HostsByIdentity: make(map[string]CompiledHost, len(cfg.Hosts)),
		LoadedAt:        time.Now().UTC(),
	}

	profileNames := sortedMapKeys(cfg.Profiles)
	for _, name := range profileNames {
		profile, err := compileProfile(name, cfg.Profiles[name])
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		compiled.Profiles[name] = profile
	}

	hostNames := sortedMapKeys(cfg.Hosts)
	for _, name := range hostNames {
		host, err := compileHost(name, cfg.Hosts[name], compiled.Profiles)
		if err != nil {
			return nil, err
		}
		if _, exists := compiled.HostsByIdentity[host.Identity]; exists {
			return nil, fmt.Errorf("duplicate identity %q", host.Identity)
		}
		compiled.HostsByName[name] = host
		compiled.HostsByIdentity[host.Identity] = host
	}

	hash, err := computePolicyHash(compiled)
	if err != nil {
		return nil, fmt.Errorf("hashing policy: %w", err)
	}
	compiled.Hash = hash

	return compiled, nil
}

func compileProfile(name string, raw Profile) (CompiledProfile, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return CompiledProfile{}, fmt.Errorf("profile name is required")
	}

	profileType := strings.TrimSpace(raw.Type)
	if profileType == "" {
		return CompiledProfile{}, fmt.Errorf("type is required")
	}

	canonicalNames, err := dnsname.CanonicalList(raw.DNSNames)
	if err != nil {
		return CompiledProfile{}, fmt.Errorf("dns_names: %w", err)
	}
	if len(canonicalNames) == 0 {
		return CompiledProfile{}, fmt.Errorf("dns_names is required")
	}

	acme := CompiledACMEProfile{
		Challenge:   strings.TrimSpace(raw.ACME.Challenge),
		Credentials: strings.TrimSpace(raw.ACME.Credentials),
	}
	if err := validateProfileType(profileType, canonicalNames, acme); err != nil {
		return CompiledProfile{}, err
	}

	renewBefore := raw.RenewBefore
	if renewBefore == 0 {
		renewBefore = defaultRenewBefore
	}
	if renewBefore < 0 {
		return CompiledProfile{}, fmt.Errorf("renew_before cannot be negative")
	}

	profile := CompiledProfile{
		Name:        name,
		Type:        profileType,
		DNSNames:    canonicalNames,
		ACME:        acme,
		RenewBefore: renewBefore,
	}

	hash, err := computeProfileHash(profile)
	if err != nil {
		return CompiledProfile{}, fmt.Errorf("hashing profile: %w", err)
	}
	profile.Hash = hash

	return profile, nil
}

func validateProfileType(profileType string, dnsNames []string, acme CompiledACMEProfile) error {
	if acme.Challenge == "" {
		return fmt.Errorf("acme.challenge is required")
	}

	switch profileType {
	case "wildcard":
		for _, name := range dnsNames {
			if !dnsname.IsValidWildcard(name) {
				return fmt.Errorf("wildcard profile contains non-wildcard name %q", name)
			}
		}
		if acme.Challenge != "dns-01" {
			return fmt.Errorf("wildcard profiles require acme.challenge dns-01")
		}

	case "multi_san":
		for _, name := range dnsNames {
			if dnsname.IsValidWildcard(name) {
				return fmt.Errorf("multi_san profile contains wildcard name %q", name)
			}
		}
		if acme.Challenge != "dns-01" {
			return fmt.Errorf("multi_san profiles require acme.challenge dns-01")
		}

	default:
		return fmt.Errorf("unsupported profile type %q", profileType)
	}

	return nil
}

func compileHost(name string, raw Host, profiles map[string]CompiledProfile) (CompiledHost, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return CompiledHost{}, fmt.Errorf("host name is required")
	}

	identity := strings.TrimSpace(raw.Identity)
	if identity == "" {
		return CompiledHost{}, fmt.Errorf("host %q identity is required", name)
	}
	if len(raw.Profiles) == 0 {
		return CompiledHost{}, fmt.Errorf("host %q must reference at least one profile", name)
	}

	allowedProfiles := make(ProfileSet, len(raw.Profiles))
	for _, profileName := range raw.Profiles {
		profileName = strings.TrimSpace(profileName)
		if profileName == "" {
			return CompiledHost{}, fmt.Errorf("host %q contains an empty profile reference", name)
		}
		if _, ok := profiles[profileName]; !ok {
			return CompiledHost{}, fmt.Errorf("host %q references unknown profile %q", name, profileName)
		}
		allowedProfiles[profileName] = true
	}

	return CompiledHost{Name: name, Identity: identity, Profiles: allowedProfiles}, nil
}

func sortedMapKeys[T any](m map[string]T) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
