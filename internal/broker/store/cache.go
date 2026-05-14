package store

// This package ontains broker persistence abstractions.
//
// The broker stores two different kinds of data: certificate cache entries and
// audit events. Runtime code depends on these interfaces rather than SQLite so
// storage can evolve without changing issuance logic.

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/TaconeoMental/certplane/internal/broker/audit"
	"github.com/TaconeoMental/certplane/internal/pki"
)

var ErrCacheMiss = errors.New("certificate cache miss")

type CertificateCacheKey struct {
	Identity           string `json:"identity"`
	ProfileName        string `json:"profile_name"`
	ProfileHash        string `json:"profile_hash"`
	PublicKeySHA256    string `json:"public_key_sha256"`
	IssuerName         string `json:"issuer_name"`
	IssuerDirectory    string `json:"issuer_directory"`
	IssuerAccountKeyID string `json:"issuer_account_key_id"`
}

func (k CertificateCacheKey) String() string {
	return k.Identity + "|" + k.ProfileName + "|" + k.ProfileHash + "|" + k.PublicKeySHA256 + "|" + k.IssuerName + "|" + k.IssuerDirectory + "|" + k.IssuerAccountKeyID
}

type CertificateStore interface {
	GetValidCertificate(ctx context.Context, key CertificateCacheKey, renewBefore time.Duration) (*pki.Bundle, error)
	PutCertificate(ctx context.Context, key CertificateCacheKey, bundle *pki.Bundle) error
	List(ctx context.Context) ([]CacheEntry, error)
}

type AuditStore interface {
	Record(ctx context.Context, event audit.Event) error
	WriteAuditEvents(ctx context.Context, w io.Writer, limit int) error
}

type Store interface {
	CertificateStore
	AuditStore
	Close() error
}

type CacheEntry struct {
	Key       CertificateCacheKey `json:"key"`
	Bundle    pki.Bundle          `json:"bundle"`
	CreatedAt time.Time           `json:"created_at"`
	UpdatedAt time.Time           `json:"updated_at"`
}
