package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/TaconeoMental/certplane/internal/pki"
)

func TestCacheKeyIncludesPublicKey(t *testing.T) {
	s := NewFileStore(filepath.Join(t.TempDir(), "cache.json"))
	ctx := context.Background()
	keyA := CertificateCacheKey{Identity: "h1", ProfileName: "edge", ProfileHash: "p", PublicKeySHA256: "a", IssuerName: "acme", IssuerDirectory: "local", IssuerAccountKeyID: "acme"}
	keyB := keyA
	keyB.PublicKeySHA256 = "b"
	bundle := &pki.Bundle{CertPEM: []byte("cert"), NotAfter: time.Now().Add(24 * time.Hour)}
	if err := s.PutCertificate(ctx, keyA, bundle); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetValidCertificate(ctx, keyB, time.Hour); err == nil {
		t.Fatal("expected cache miss for different public key")
	}
}
