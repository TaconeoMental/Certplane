package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// newTestCert creates a self signed certificate for test use
func newTestCert(t *testing.T, key *ecdsa.PrivateKey, dnsNames []string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// marshalPublicKey is a helper that fails if the marshal fails
func marshalPublicKey(t *testing.T, pub any) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return der
}

// key.go

func TestGenerateECDSAKey(t *testing.T) {
	key, err := GenerateECDSAKey()
	if err != nil {
		t.Fatal(err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if key.Curve.Params().Name != "P-256" {
		t.Fatalf("expected P-256, got %s", key.Curve.Params().Name)
	}
}

func TestMarshalParsePrivateKeyRoundTrip(t *testing.T) {
	key, err := GenerateECDSAKey()
	if err != nil {
		t.Fatal(err)
	}
	pemData, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePrivateKeyPEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	origDER := marshalPublicKey(t, key.Public())
	parsedDER := marshalPublicKey(t, parsed.Public())
	if !bytes.Equal(origDER, parsedDER) {
		t.Fatal("parsed key public key does not match original")
	}
}

func TestParsePrivateKeyPEMECFormat(t *testing.T) {
	// Verifies the (legacy format) "EC PRIVATE KEY" path of
	// ParsePrivateKeyPEM.
	key, err := GenerateECDSAKey()
	if err != nil {
		t.Fatal(err)
	}
	legacyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	legacyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: legacyDER})
	parsed, err := ParsePrivateKeyPEM(legacyPEM)
	if err != nil {
		t.Fatalf("expected EC PRIVATE KEY to parse: %v", err)
	}
	if !bytes.Equal(marshalPublicKey(t, key.Public()), marshalPublicKey(t, parsed.Public())) {
		t.Fatal("parsed EC key public key does not match original")
	}
}

func TestParsePrivateKeyPEMErrors(t *testing.T) {
	if _, err := ParsePrivateKeyPEM([]byte("not pem")); err == nil {
		t.Fatal("expected error for non-PEM data")
	}
	if _, err := ParsePrivateKeyPEM([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n")); err == nil {
		t.Fatal("expected error for wrong PEM block type")
	}
}

func TestEnsureECDSAPrivateKeyCreatesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	key, pemData, err := EnsureECDSAPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if key == nil || len(pemData) == 0 {
		t.Fatal("expected key and PEM data")
	}
	// Verifies that the written file is a parseable key
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if _, err := ParsePrivateKeyPEM(data); err != nil {
		t.Fatalf("key file contains invalid key: %v", err)
	}
}

func TestEnsureECDSAPrivateKeyLoadsExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.pem")
	key1, _, err := EnsureECDSAPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	key2, _, err := EnsureECDSAPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	der1 := marshalPublicKey(t, key1.Public())
	der2 := marshalPublicKey(t, key2.Public())
	if !bytes.Equal(der1, der2) {
		t.Fatal("second call loaded a different key")
	}
}

// cert.go

func TestParseCertificatePEM(t *testing.T) {
	key, _ := GenerateECDSAKey()
	cert := newTestCert(t, key, nil, time.Now().Add(time.Hour))
	pemData := EncodeCertPEM(cert)

	parsed, err := ParseCertificatePEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("serial number mismatch")
	}
}

func TestParseCertificatePEMErrors(t *testing.T) {
	if _, err := ParseCertificatePEM([]byte("not pem")); err == nil {
		t.Fatal("expected error for non-PEM data")
	}
	// Incorrect block type
	key, _ := GenerateECDSAKey()
	csrPEM, _ := GenerateIdentityCSR(key, "test")
	if _, err := ParseCertificatePEM(csrPEM); err == nil {
		t.Fatal("expected error for wrong PEM block type")
	}
	// Corrupt DER inside a valid CERTIFICATE block
	corrupted := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not valid der")})
	if _, err := ParseCertificatePEM(corrupted); err == nil {
		t.Fatal("expected error for corrupted DER")
	}
}

func TestEncodeCertPEMRoundTrip(t *testing.T) {
	key, _ := GenerateECDSAKey()
	cert := newTestCert(t, key, nil, time.Now().Add(time.Hour))
	pemData := EncodeCertPEM(cert)
	parsed, err := ParseCertificatePEM(pemData)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Raw, cert.Raw) {
		t.Fatal("round-trip produced different certificate")
	}
}

func TestExpiresWithin(t *testing.T) {
	key, _ := GenerateECDSAKey()
	cert := newTestCert(t, key, nil, time.Now().Add(time.Hour))

	if !ExpiresWithin(cert, 2*time.Hour) {
		t.Fatal("expected true: cert expires within 2h")
	}
	if ExpiresWithin(cert, 30*time.Minute) {
		t.Fatal("expected false: cert does not expire within 30m")
	}
}

func TestIsExpired(t *testing.T) {
	key, _ := GenerateECDSAKey()

	expired := newTestCert(t, key, nil, time.Now().Add(-time.Minute))
	if !IsExpired(expired) {
		t.Fatal("expected expired cert to be expired")
	}

	valid := newTestCert(t, key, nil, time.Now().Add(time.Hour))
	if IsExpired(valid) {
		t.Fatal("expected valid cert to not be expired")
	}
}

func TestCertificateMatchesPrivateKey(t *testing.T) {
	key, _ := GenerateECDSAKey()
	cert := newTestCert(t, key, nil, time.Now().Add(time.Hour))

	if err := CertificateMatchesPrivateKey(cert, key); err != nil {
		t.Fatalf("expected match: %v", err)
	}

	otherKey, _ := GenerateECDSAKey()
	if err := CertificateMatchesPrivateKey(cert, otherKey); err == nil {
		t.Fatal("expected mismatch error for different key")
	}
}

func TestSerialString(t *testing.T) {
	if s := SerialString(nil); s != "" {
		t.Fatalf("expected empty string for nil, got %q", s)
	}
	n := big.NewInt(255)
	if s := SerialString(n); s != "ff" {
		t.Fatalf("expected %q, got %q", "ff", s)
	}
}

func TestCertificateHasExactDNSNames(t *testing.T) {
	key, _ := GenerateECDSAKey()
	names := []string{"api.example.com", "api-v2.example.com"}
	cert := newTestCert(t, key, names, time.Now().Add(time.Hour))

	if err := CertificateHasExactDNSNames(cert, names); err != nil {
		t.Fatalf("expected exact match: %v", err)
	}
	if err := CertificateHasExactDNSNames(cert, []string{"api.example.com"}); err == nil {
		t.Fatal("expected error for subset")
	}
	if err := CertificateHasExactDNSNames(cert, append(names, "extra.example.com")); err == nil {
		t.Fatal("expected error for superset")
	}
}

// csr.go

func TestGenerateIdentityCSR(t *testing.T) {
	key, _ := GenerateECDSAKey()
	csrPEM, err := GenerateIdentityCSR(key, "node01")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "node01" {
		t.Fatalf("expected CN %q, got %q", "node01", csr.Subject.CommonName)
	}
}

func TestGenerateIdentityCSREmptyIdentity(t *testing.T) {
	key, _ := GenerateECDSAKey()
	if _, err := GenerateIdentityCSR(key, "   "); err == nil {
		t.Fatal("expected error for empty identity")
	}
}

func TestGenerateServiceCSR(t *testing.T) {
	key, _ := GenerateECDSAKey()
	// CanonicalList orders alphabetically, so "api-v2.example.com" comes
	// before than "api.example.com"
	csrPEM, err := GenerateServiceCSR(key, []string{"api.example.com", "api-v2.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseCSRPEM(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api-v2.example.com", "api.example.com"}
	if len(csr.DNSNames) != len(want) {
		t.Fatalf("expected %d DNS names, got %d: %v", len(want), len(csr.DNSNames), csr.DNSNames)
	}
	for i, name := range want {
		if csr.DNSNames[i] != name {
			t.Fatalf("DNSNames[%d]: expected %q, got %q", i, name, csr.DNSNames[i])
		}
	}
}

func TestGenerateServiceCSREmptyNames(t *testing.T) {
	key, _ := GenerateECDSAKey()
	if _, err := GenerateServiceCSR(key, []string{}); err == nil {
		t.Fatal("expected error for empty names")
	}
}

func TestParseCSRPEMErrors(t *testing.T) {
	if _, err := ParseCSRPEM([]byte("not pem")); err == nil {
		t.Fatal("expected error for non-PEM data")
	}
	key, _ := GenerateECDSAKey()
	certPEM := EncodeCertPEM(newTestCert(t, key, nil, time.Now().Add(time.Hour)))
	if _, err := ParseCSRPEM(certPEM); err == nil {
		t.Fatal("expected error for wrong PEM block type")
	}
}

func TestPublicKeyFingerprint(t *testing.T) {
	key, _ := GenerateECDSAKey()
	fp1, err := PublicKeyFingerprint(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	fp2, err := PublicKeyFingerprint(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if fp1 != fp2 {
		t.Fatal("same key produced different fingerprints")
	}

	other, _ := GenerateECDSAKey()
	fp3, err := PublicKeyFingerprint(other.Public())
	if err != nil {
		t.Fatal(err)
	}
	if fp1 == fp3 {
		t.Fatal("different keys produced same fingerprint")
	}
}

func TestCSRFingerprint(t *testing.T) {
	key, _ := GenerateECDSAKey()
	csrPEM, _ := GenerateIdentityCSR(key, "node01")

	fp1 := CSRFingerprint(csrPEM)
	fp2 := CSRFingerprint(csrPEM)
	if fp1 != fp2 {
		t.Fatal("same CSR produced different fingerprints")
	}

	csrPEM2, _ := GenerateIdentityCSR(key, "node02")
	if CSRFingerprint(csrPEM) == CSRFingerprint(csrPEM2) {
		t.Fatal("different CSRs produced same fingerprint")
	}
}

// bundle.go

func TestBundleWriteToDisk(t *testing.T) {
	dir := t.TempDir()
	b := &Bundle{
		CertPEM:      []byte("cert"),
		ChainPEM:     []byte("chain"),
		FullChainPEM: []byte("fullchain"),
	}
	certPath := filepath.Join(dir, "cert.pem")
	chainPath := filepath.Join(dir, "chain.pem")
	fullchainPath := filepath.Join(dir, "fullchain.pem")

	if err := b.WriteToDisk(certPath, chainPath, fullchainPath); err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]string{
		certPath:      "cert",
		chainPath:     "chain",
		fullchainPath: "fullchain",
	} {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		if string(got) != want {
			t.Fatalf("%s: expected %q, got %q", path, want, string(got))
		}
	}
}
