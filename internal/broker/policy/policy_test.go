package policy

import (
	"testing"

	"github.com/TaconeoMental/certplane/internal/pki"
)

func testPolicy(t *testing.T) *CompiledPolicy {
	t.Helper()
	pol, err := Compile(Config{
		Version: 1,
		Profiles: map[string]Profile{
			"edge": {Type: "wildcard", DNSNames: []string{"*.whisper.cl"}, ACME: ACMEProfile{Challenge: "dns-01", Credentials: "cf"}},
			"api":  {Type: "multi_san", DNSNames: []string{"api.whisper.cl", "api-v2.whisper.cl"}, ACME: ACMEProfile{Challenge: "dns-01", Credentials: "cf"}},
		},
		Hosts: map[string]Host{
			"edge01": {Identity: "edge01", Profiles: []string{"edge"}},
			"api01":  {Identity: "api01", Profiles: []string{"api"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return pol
}

func TestAuthorizeExactSANMatch(t *testing.T) {
	pol := testPolicy(t)
	key, err := pki.GenerateECDSAKey()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := pki.GenerateServiceCSR(key, []string{"*.WHISPER.CL."})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pol.Authorize("edge01", "edge", csr); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorizeRejectsSuperset(t *testing.T) {
	pol := testPolicy(t)
	key, err := pki.GenerateECDSAKey()
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := pki.GenerateServiceCSR(key, []string{"api.whisper.cl", "api-v2.whisper.cl", "extra.whisper.cl"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pol.Authorize("api01", "api", csr); err == nil {
		t.Fatal("expected mismatch")
	}
}

func TestMultiSANRejectsNonDNS01Challenge(t *testing.T) {
	_, err := Compile(Config{
		Version: 1,
		Profiles: map[string]Profile{
			"api": {Type: "multi_san", DNSNames: []string{"api.whisper.cl"}, ACME: ACMEProfile{Challenge: "http-01", Credentials: "cf"}},
		},
		Hosts: map[string]Host{
			"api01": {Identity: "api01", Profiles: []string{"api"}},
		},
	})
	if err == nil {
		t.Fatal("expected error for multi_san with http-01 challenge")
	}
}

func TestDuplicateIdentityRejected(t *testing.T) {
	_, err := Compile(Config{
		Version:  1,
		Profiles: map[string]Profile{"edge": {Type: "wildcard", DNSNames: []string{"*.whisper.cl"}, ACME: ACMEProfile{Challenge: "dns-01", Credentials: "cf"}}},
		Hosts: map[string]Host{
			"a": {Identity: "same", Profiles: []string{"edge"}},
			"b": {Identity: "same", Profiles: []string{"edge"}},
		},
	})
	if err == nil {
		t.Fatal("expected duplicate identity error")
	}
}
