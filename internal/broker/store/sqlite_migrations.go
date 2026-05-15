package store

import (
	"context"
	"database/sql"
	"fmt"
)

type sqliteMigration struct {
	Version int
	Name    string
	SQL     string
}

var sqliteMigrations = []sqliteMigration{
	{
		Version: 1,
		Name:    "initial_schema",
		SQL: `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS certificate_cache (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  identity TEXT NOT NULL,
  profile_name TEXT NOT NULL,
  profile_hash TEXT NOT NULL,
  public_key_sha256 TEXT NOT NULL,

  issuer_name TEXT NOT NULL,
  issuer_directory TEXT NOT NULL,
  issuer_account_key_id TEXT NOT NULL,

  cert_pem BLOB NOT NULL,
  chain_pem BLOB NOT NULL,
  fullchain_pem BLOB NOT NULL,

  serial_number TEXT NOT NULL,
  not_before TEXT NOT NULL,
  not_after TEXT NOT NULL,

  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,

  UNIQUE (
    identity,
    profile_name,
    profile_hash,
    public_key_sha256,
    issuer_name,
    issuer_directory,
    issuer_account_key_id
  )
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  event_id TEXT NOT NULL UNIQUE,
  request_id TEXT NOT NULL,
  timestamp TEXT NOT NULL,

  event_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  decision TEXT NOT NULL,

  identity TEXT,
  profile_name TEXT,
  profile_hash TEXT,
  policy_hash TEXT,

  reason_code TEXT,
  reason TEXT,
  error TEXT,

  source_ip TEXT,
  user_agent TEXT,

  csr_sha256 TEXT,
  csr_public_key_sha256 TEXT,
  csr_dns_names_json TEXT,
  expected_dns_names_json TEXT,

  issuer_name TEXT,
  issuer_directory TEXT,
  acme_order_url TEXT,

  cert_serial_number TEXT,
  cert_not_before TEXT,
  cert_not_after TEXT,

  cache_result TEXT,
  metadata_json TEXT,

  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_certificate_cache_lookup
ON certificate_cache (
  identity,
  profile_name,
  profile_hash,
  public_key_sha256,
  issuer_name,
  issuer_directory,
  issuer_account_key_id
);

CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp
ON audit_events(timestamp);

CREATE INDEX IF NOT EXISTS idx_audit_events_identity
ON audit_events(identity);

CREATE INDEX IF NOT EXISTS idx_audit_events_profile
ON audit_events(profile_name);

CREATE INDEX IF NOT EXISTS idx_audit_events_decision
ON audit_events(decision);
`,
	},
}

func (s *SQLiteStore) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("starting sqlite migration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := ensureMigrationTable(ctx, tx); err != nil {
		return err
	}

	for _, migration := range sqliteMigrations {
		applied, err := migrationAlreadyApplied(ctx, tx, migration.Version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}

		if _, err := tx.ExecContext(ctx, migration.SQL); err != nil {
			return fmt.Errorf("applying migration %d %s: %w", migration.Version, migration.Name, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, datetime('now'))`, migration.Version, migration.Name); err != nil {
			return fmt.Errorf("recording migration %d %s: %w", migration.Version, migration.Name, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing sqlite migrations: %w", err)
	}
	return nil
}

func ensureMigrationTable(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  applied_at TEXT NOT NULL
)`)
	if err != nil {
		return fmt.Errorf("ensuring schema_migrations table: %w", err)
	}
	return nil
}

func migrationAlreadyApplied(ctx context.Context, tx *sql.Tx, version int) (bool, error) {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM schema_migrations WHERE version = ?`, version).Scan(&count); err != nil {
		return false, fmt.Errorf("checking migration %d: %w", version, err)
	}
	return count > 0, nil
}
