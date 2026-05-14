package policy

// Authorize checks whether an authenticated agent identity may request a
// profile, then verifies that the untrusted CSR requests exactly the DNS names
// defined by that profile.

import (
	"crypto/x509"
	"fmt"

	"github.com/TaconeoMental/certplane/internal/dnsname"
)

func (p *CompiledPolicy) Authorize(identity, profileName string, csr *x509.CertificateRequest) (*CompiledProfile, error) {
	if csr == nil {
		return nil, ErrInvalidCSR
	}

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
		return &profile, fmt.Errorf("%w: %v", ErrInvalidCSR, err)
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
