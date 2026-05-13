package policy

// This file contains the hashing helpers used to identify the effective policy
// state.
//
// These hashes are used for certificate cache invalidation and auditability,
// and identify the policy/profile version under which a certificate was
// issued.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

type profileHashInput struct {
	Type        string              `json:"type"`
	DNSNames    []string            `json:"dns_names"`
	ACME        CompiledACMEProfile `json:"acme"`
	RenewBefore string              `json:"renew_before"`
}

type policyHashInput struct {
	Version  int                 `json:"version"`
	Profiles []profileHashRecord `json:"profiles"`
	Hosts    []hostHashRecord    `json:"hosts"`
}

type profileHashRecord struct {
	Name string `json:"name"`
	Hash string `json:"hash"`
}

type hostHashRecord struct {
	Name     string   `json:"name"`
	Identity string   `json:"identity"`
	Profiles []string `json:"profiles"`
}

func computeProfileHash(profile CompiledProfile) (string, error) {
	return hashCanonical(profileHashInput{
		Type:        profile.Type,
		DNSNames:    profile.DNSNames,
		ACME:        profile.ACME,
		RenewBefore: profile.RenewBefore.String(),
	})
}

func computePolicyHash(policy *CompiledPolicy) (string, error) {
	input := policyHashInput{Version: policy.Version}

	profileNames := sortedMapKeys(policy.Profiles)
	input.Profiles = make([]profileHashRecord, 0, len(profileNames))
	for _, name := range profileNames {
		profile := policy.Profiles[name]
		input.Profiles = append(input.Profiles, profileHashRecord{Name: profile.Name, Hash: profile.Hash})
	}

	hostNames := sortedMapKeys(policy.HostsByName)
	input.Hosts = make([]hostHashRecord, 0, len(hostNames))
	for _, name := range hostNames {
		host := policy.HostsByName[name]
		profiles := make([]string, 0, len(host.Profiles))
		for profileName := range host.Profiles {
			profiles = append(profiles, profileName)
		}
		sort.Strings(profiles)
		input.Hosts = append(input.Hosts, hostHashRecord{Name: host.Name, Identity: host.Identity, Profiles: profiles})
	}

	return hashCanonical(input)
}

func hashCanonical(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshaling canonical policy data: %w", err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
