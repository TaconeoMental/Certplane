package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/TaconeoMental/certplane/internal/broker/audit"
)

type auditEventRow struct {
	EventID   string
	RequestID string
	Timestamp string

	Type     string
	Severity string
	Decision string

	Identity    sql.NullString
	ProfileName sql.NullString
	ProfileHash sql.NullString
	PolicyHash  sql.NullString

	ReasonCode sql.NullString
	Reason     sql.NullString
	Error      sql.NullString

	SourceIP  sql.NullString
	UserAgent sql.NullString

	CSRSHA256          sql.NullString
	CSRPublicKeySHA256 sql.NullString
	CSRDNSNamesJSON    sql.NullString
	ExpectedNamesJSON  sql.NullString

	IssuerName      sql.NullString
	IssuerDirectory sql.NullString
	ACMEOrderURL    sql.NullString

	LeafSerialNumber sql.NullString
	CertNotBefore    sql.NullString
	CertNotAfter     sql.NullString

	CacheResult  sql.NullString
	MetadataJSON sql.NullString
}

func (r *auditEventRow) scan(row rowScanner) error {
	return row.Scan(
		&r.EventID,
		&r.RequestID,
		&r.Timestamp,
		&r.Type,
		&r.Severity,
		&r.Decision,
		&r.Identity,
		&r.ProfileName,
		&r.ProfileHash,
		&r.PolicyHash,
		&r.ReasonCode,
		&r.Reason,
		&r.Error,
		&r.SourceIP,
		&r.UserAgent,
		&r.CSRSHA256,
		&r.CSRPublicKeySHA256,
		&r.CSRDNSNamesJSON,
		&r.ExpectedNamesJSON,
		&r.IssuerName,
		&r.IssuerDirectory,
		&r.ACMEOrderURL,
		&r.LeafSerialNumber,
		&r.CertNotBefore,
		&r.CertNotAfter,
		&r.CacheResult,
		&r.MetadataJSON,
	)
}

func (r auditEventRow) auditEvent() (audit.Event, error) {
	timestamp, err := parseRequiredTime(r.Timestamp, "timestamp")
	if err != nil {
		return audit.Event{}, err
	}
	certNotBefore, err := parseOptionalTime(r.CertNotBefore, "cert_not_before")
	if err != nil {
		return audit.Event{}, err
	}
	certNotAfter, err := parseOptionalTime(r.CertNotAfter, "cert_not_after")
	if err != nil {
		return audit.Event{}, err
	}

	event := audit.Event{
		EventID:            r.EventID,
		RequestID:          r.RequestID,
		Timestamp:          timestamp,
		Type:               audit.EventType(r.Type),
		Severity:           audit.Severity(r.Severity),
		Decision:           audit.Decision(r.Decision),
		Identity:           stringFromNull(r.Identity),
		ProfileName:        stringFromNull(r.ProfileName),
		ProfileHash:        stringFromNull(r.ProfileHash),
		PolicyHash:         stringFromNull(r.PolicyHash),
		ReasonCode:         stringFromNull(r.ReasonCode),
		Reason:             stringFromNull(r.Reason),
		Error:              stringFromNull(r.Error),
		SourceIP:           stringFromNull(r.SourceIP),
		UserAgent:          stringFromNull(r.UserAgent),
		CSRSHA256:          stringFromNull(r.CSRSHA256),
		CSRPublicKeySHA256: stringFromNull(r.CSRPublicKeySHA256),
		IssuerName:         stringFromNull(r.IssuerName),
		IssuerDirectory:    stringFromNull(r.IssuerDirectory),
		ACMEOrderURL:       stringFromNull(r.ACMEOrderURL),
		CertSerialNumber:   stringFromNull(r.LeafSerialNumber),
		CertNotBefore:      certNotBefore,
		CertNotAfter:       certNotAfter,
		CacheResult:        stringFromNull(r.CacheResult),
	}

	if err := decodeJSON(r.CSRDNSNamesJSON, &event.CSRDNSNames, "csr_dns_names_json"); err != nil {
		return audit.Event{}, err
	}
	if err := decodeJSON(r.ExpectedNamesJSON, &event.ExpectedDNSNames, "expected_dns_names_json"); err != nil {
		return audit.Event{}, err
	}
	if err := decodeJSON(r.MetadataJSON, &event.Metadata, "metadata_json"); err != nil {
		return audit.Event{}, err
	}

	return event, nil
}

func (s *SQLiteStore) Record(ctx context.Context, event audit.Event) error {
	csrNames, err := encodeJSON(event.CSRDNSNames, "csr_dns_names")
	if err != nil {
		return err
	}
	expectedNames, err := encodeJSON(event.ExpectedDNSNames, "expected_dns_names")
	if err != nil {
		return err
	}
	metadata, err := encodeJSON(event.Metadata, "metadata")
	if err != nil {
		return err
	}

	_, err = s.db.ExecContext(ctx, insertAuditEventSQL,
		event.EventID,
		event.RequestID,
		event.Timestamp.UTC().Format(time.RFC3339),
		string(event.Type),
		string(event.Severity),
		string(event.Decision),
		nullableString(event.Identity),
		nullableString(event.ProfileName),
		nullableString(event.ProfileHash),
		nullableString(event.PolicyHash),
		nullableString(event.ReasonCode),
		nullableString(event.Reason),
		nullableString(event.Error),
		nullableString(event.SourceIP),
		nullableString(event.UserAgent),
		nullableString(event.CSRSHA256),
		nullableString(event.CSRPublicKeySHA256),
		csrNames,
		expectedNames,
		nullableString(event.IssuerName),
		nullableString(event.IssuerDirectory),
		nullableString(event.ACMEOrderURL),
		nullableString(event.CertSerialNumber),
		nullableTime(event.CertNotBefore),
		nullableTime(event.CertNotAfter),
		nullableString(event.CacheResult),
		metadata,
	)
	if err != nil {
		return fmt.Errorf("recording audit event: %w", err)
	}
	return nil
}

func (s *SQLiteStore) WriteAuditEvents(ctx context.Context, w io.Writer, limit int) error {
	events, err := s.listAuditEvents(ctx, limit)
	if err != nil {
		return err
	}

	encoder := json.NewEncoder(w)
	for _, event := range events {
		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("writing audit event: %w", err)
		}
	}
	return nil
}

func (s *SQLiteStore) listAuditEvents(ctx context.Context, limit int) ([]audit.Event, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.QueryContext(ctx, listAuditEventsSQL, limit)
	if err != nil {
		return nil, fmt.Errorf("listing audit events: %w", err)
	}
	defer rows.Close()

	events := make([]audit.Event, 0, limit)
	for rows.Next() {
		var row auditEventRow
		if err := row.scan(rows); err != nil {
			return nil, fmt.Errorf("scanning audit event row: %w", err)
		}
		event, err := row.auditEvent()
		if err != nil {
			return nil, fmt.Errorf("decoding audit event row: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating audit event rows: %w", err)
	}
	return events, nil
}

var listAuditEventsSQL = `
SELECT ` + columnList(auditEventColumns) + `
FROM audit_events
ORDER BY timestamp DESC
LIMIT ?`

const insertAuditEventSQL = `
INSERT INTO audit_events (
  event_id,
  request_id,
  timestamp,
  event_type,
  severity,
  decision,
  identity,
  profile_name,
  profile_hash,
  policy_hash,
  reason_code,
  reason,
  error,
  source_ip,
  user_agent,
  csr_sha256,
  csr_public_key_sha256,
  csr_dns_names_json,
  expected_dns_names_json,
  issuer_name,
  issuer_directory,
  acme_order_url,
  cert_serial_number,
  cert_not_before,
  cert_not_after,
  cache_result,
  metadata_json,
  created_at
)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`

