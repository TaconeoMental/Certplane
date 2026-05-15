package store

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TaconeoMental/certplane/internal/broker/audit"
	"github.com/TaconeoMental/certplane/internal/fileutil"
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
	return strings.Join([]string{
		k.Identity,
		k.ProfileName,
		k.ProfileHash,
		k.PublicKeySHA256,
		k.IssuerName,
		k.IssuerDirectory,
		k.IssuerAccountKeyID,
	}, "\x00")
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

type FileStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(path string) *FileStore {
	return &FileStore{path: path}
}

func (s *FileStore) GetValidCertificate(ctx context.Context, key CertificateCacheKey, renewBefore time.Duration) (*pki.Bundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.loadLocked()
	if err != nil {
		return nil, err
	}

	entry, ok := entries[key.String()]
	if !ok {
		return nil, ErrCacheMiss
	}
	if time.Until(entry.Bundle.NotAfter) <= renewBefore {
		return nil, ErrCacheMiss
	}

	bundle := entry.Bundle
	return &bundle, nil
}

func (s *FileStore) PutCertificate(ctx context.Context, key CertificateCacheKey, bundle *pki.Bundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.loadLocked()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	createdAt := entries[key.String()].CreatedAt
	if createdAt.IsZero() {
		createdAt = now
	}

	entries[key.String()] = CacheEntry{
		Key:       key,
		Bundle:    *bundle,
		CreatedAt: createdAt,
		UpdatedAt: now,
	}

	return s.saveLocked(entries)
}

func (s *FileStore) List(ctx context.Context) ([]CacheEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := s.loadLocked()
	if err != nil {
		return nil, err
	}

	out := make([]CacheEntry, 0, len(entries))
	for _, entry := range entries {
		out = append(out, entry)
	}
	return out, nil
}

func (s *FileStore) Record(ctx context.Context, event audit.Event) error {
	path := s.path + ".audit.jsonl"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("opening file audit store %q: %w", path, err)
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(event); err != nil {
		return fmt.Errorf("writing file audit event: %w", err)
	}
	return file.Sync()
}

func (s *FileStore) WriteAuditEvents(ctx context.Context, w io.Writer, limit int) error {
	path := s.path + ".audit.jsonl"
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("opening file audit store %q: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		if limit > 0 && count >= limit {
			break
		}
		if _, err := fmt.Fprintln(w, scanner.Text()); err != nil {
			return fmt.Errorf("writing audit event: %w", err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("reading file audit store %q: %w", path, err)
	}
	return nil
}

func (s *FileStore) Close() error { return nil }

func (s *FileStore) loadLocked() (map[string]CacheEntry, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]CacheEntry{}, nil
		}
		return nil, fmt.Errorf("reading cache %q: %w", s.path, err)
	}

	var entries map[string]CacheEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("parsing cache %q: %w", s.path, err)
	}
	if entries == nil {
		entries = map[string]CacheEntry{}
	}
	return entries, nil
}

func (s *FileStore) saveLocked(entries map[string]CacheEntry) error {
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling cache: %w", err)
	}
	if err := fileutil.WriteFileAtomic(s.path, data, 0o600); err != nil {
		return fmt.Errorf("writing cache %q atomically: %w", s.path, err)
	}
	return nil
}
