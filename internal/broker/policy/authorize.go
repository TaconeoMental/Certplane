package policy

// This file contains the broker authorization logic.
//
// Authorization starts from the authenticated agent identity extracted from
// the mTLS client certificate. The broker checks whether that identity is
// allowed to request the selected profile, then validates that the CSR DNS
// names exactly match the DNS names defined by that profile.

import (
	"crypto/x509"
	"fmt"

	"github.com/TaconeoMental/certplane/internal/dnsname"
)

func (p *CompiledPolicy) Authorize(identity, profileName string, csr *x509.CertificateRequest) (*CompiledProfile, error) {
	host, ok := p.HostsByIdentity[identity]
	if !ok {
		return nil, ErrUnknownIdentity
	}
	if !host.AllowsProfile(profileName) {
		return nil, ErrProfileNotAllowed
	}

	profile, ok := p.Profiles[profileName]
	if !ok {
		return nil, ErrUnknownProfile
	}

	csrNames, err := dnsname.CanonicalList(csr.DNSNames)
	if err != nil {
		return &profile, fmt.Errorf("invalid CSR DNS names: %w", err)
	}
	if !sameStringSet(csrNames, profile.DNSNames) {
		return &profile, ErrCSRNamesMismatch
	}

	return &profile, nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
