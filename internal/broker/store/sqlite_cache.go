package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/TaconeoMental/certplane/internal/pki"
)

type certificateCacheRow struct {
	Identity           string
	ProfileName        string
	ProfileHash        string
	PublicKeySHA256    string
	IssuerName         string
	IssuerDirectory    string
	IssuerAccountKeyID string

	CertPEM          []byte
	ChainPEM         []byte
	FullChainPEM     []byte
	LeafLeafSerialNumber string

	NotBefore string
	NotAfter  string
	CreatedAt string
	UpdatedAt string
}

type rowScanner interface {
	Scan(dest ...any) error
}

func (r *certificateCacheRow) scan(row rowScanner) error {
	return row.Scan(
		&r.Identity,
		&r.ProfileName,
		&r.ProfileHash,
		&r.PublicKeySHA256,
		&r.IssuerName,
		&r.IssuerDirectory,
		&r.IssuerAccountKeyID,
		&r.CertPEM,
		&r.ChainPEM,
		&r.FullChainPEM,
		&r.LeafLeafSerialNumber,
		&r.NotBefore,
		&r.NotAfter,
		&r.CreatedAt,
		&r.UpdatedAt,
	)
}

func (r certificateCacheRow) cacheEntry() (CacheEntry, error) {
	notBefore, err := parseRequiredTime(r.NotBefore, "not_before")
	if err != nil {
		return CacheEntry{}, err
	}
	notAfter, err := parseRequiredTime(r.NotAfter, "not_after")
	if err != nil {
		return CacheEntry{}, err
	}
	createdAt, err := parseRequiredTime(r.CreatedAt, "created_at")
	if err != nil {
		return CacheEntry{}, err
	}
	updatedAt, err := parseRequiredTime(r.UpdatedAt, "updated_at")
	if err != nil {
		return CacheEntry{}, err
	}

	return CacheEntry{
		Key: CertificateCacheKey{
			Identity:           r.Identity,
			ProfileName:        r.ProfileName,
			ProfileHash:        r.ProfileHash,
			PublicKeySHA256:    r.PublicKeySHA256,
			IssuerName:         r.IssuerName,
			IssuerDirectory:    r.IssuerDirectory,
			IssuerAccountKeyID: r.IssuerAccountKeyID,
		},
		Bundle: pki.Bundle{
			CertPEM:      r.CertPEM,
			ChainPEM:     r.ChainPEM,
			FullChainPEM: r.FullChainPEM,
			LeafSerialNumber: r.LeafLeafSerialNumber,
			NotBefore:    notBefore,
			NotAfter:     notAfter,
		},
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
	}, nil
}

// Returns a cached bundle only if it is outside the renewal window. If the
// enries are missing, expired or close enough to expiry, they are treated as
// cache misses so the caller can issue a fresh certificate.
func (s *SQLiteStore) GetValidCertificate(ctx context.Context, key CertificateCacheKey, renewBefore time.Duration) (*pki.Bundle, error) {
	row, err := s.readCertificateCacheRow(ctx, key)
	if err != nil {
		return nil, err
	}

	entry, err := row.cacheEntry()
	if err != nil {
		return nil, fmt.Errorf("decoding certificate cache row: %w", err)
	}
	if time.Until(entry.Bundle.NotAfter) <= renewBefore {
		return nil, ErrCacheMiss
	}

	bundle := entry.Bundle
	return &bundle, nil
}

func (s *SQLiteStore) PutCertificate(ctx context.Context, key CertificateCacheKey, bundle *pki.Bundle) error {
	if bundle == nil {
		return fmt.Errorf("certificate bundle is nil")
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.ExecContext(ctx, insertCertificateCacheSQL,
		key.Identity,
		key.ProfileName,
		key.ProfileHash,
		key.PublicKeySHA256,
		key.IssuerName,
		key.IssuerDirectory,
		key.IssuerAccountKeyID,
		bundle.CertPEM,
		bundle.ChainPEM,
		bundle.FullChainPEM,
		bundle.LeafSerialNumber,
		bundle.NotBefore.UTC().Format(time.RFC3339),
		bundle.NotAfter.UTC().Format(time.RFC3339),
		now,
		now,
	)
	if err != nil {
		return fmt.Errorf("writing certificate cache: %w", err)
	}
	return nil
}

func (s *SQLiteStore) List(ctx context.Context) ([]CacheEntry, error) {
	rows, err := s.db.QueryContext(ctx, listCertificateCacheSQL)
	if err != nil {
		return nil, fmt.Errorf("listing certificate cache: %w", err)
	}
	defer rows.Close()

	entries := []CacheEntry{}
	for rows.Next() {
		var row certificateCacheRow
		if err := row.scan(rows); err != nil {
			return nil, fmt.Errorf("scanning certificate cache row: %w", err)
		}
		entry, err := row.cacheEntry()
		if err != nil {
			return nil, fmt.Errorf("decoding certificate cache row: %w", err)
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating certificate cache rows: %w", err)
	}
	return entries, nil
}

func (s *SQLiteStore) readCertificateCacheRow(ctx context.Context, key CertificateCacheKey) (certificateCacheRow, error) {
	var row certificateCacheRow
	err := row.scan(s.db.QueryRowContext(ctx, getCertificateCacheSQL,
		key.Identity,
		key.ProfileName,
		key.ProfileHash,
		key.PublicKeySHA256,
		key.IssuerName,
		key.IssuerDirectory,
		key.IssuerAccountKeyID,
	))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return certificateCacheRow{}, ErrCacheMiss
		}
		return certificateCacheRow{}, fmt.Errorf("reading certificate cache: %w", err)
	}
	return row, nil
}

var getCertificateCacheSQL = `
SELECT ` + columnList(certificateCacheColumns) + `
FROM certificate_cache
WHERE identity = ?
  AND profile_name = ?
  AND profile_hash = ?
  AND public_key_sha256 = ?
  AND issuer_name = ?
  AND issuer_directory = ?
  AND issuer_account_key_id = ?
LIMIT 1`

var listCertificateCacheSQL = `
SELECT ` + columnList(certificateCacheColumns) + `
FROM certificate_cache
ORDER BY updated_at DESC`

const insertCertificateCacheSQL = `
INSERT INTO certificate_cache (
  identity,
  profile_name,
  profile_hash,
  public_key_sha256,
  issuer_name,
  issuer_directory,
  issuer_account_key_id,
  cert_pem,
  chain_pem,
  fullchain_pem,
  serial_number,
  not_before,
  not_after,
  created_at,
  updated_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (
  identity,
  profile_name,
  profile_hash,
  public_key_sha256,
  issuer_name,
  issuer_directory,
  issuer_account_key_id
)
DO UPDATE SET
  cert_pem = excluded.cert_pem,
  chain_pem = excluded.chain_pem,
  fullchain_pem = excluded.fullchain_pem,
  serial_number = excluded.serial_number,
  not_before = excluded.not_before,
  not_after = excluded.not_after,
  updated_at = excluded.updated_at`

