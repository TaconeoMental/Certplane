package store

// These helpers keep null, time and JSON encoding rules consistent across
// cache and audit repositories.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

func nullableString(value string) sql.NullString {
	if value == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func stringFromNull(value sql.NullString) string {
	if !value.Valid {
		return ""
	}
	return value.String
}

func nullableTime(value *time.Time) sql.NullString {
	if value == nil || value.IsZero() {
		return sql.NullString{}
	}
	return sql.NullString{String: value.UTC().Format(time.RFC3339), Valid: true}
}

func parseRequiredTime(value, field string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("%s is empty", field)
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parsing %s %q: %w", field, value, err)
	}
	return parsed, nil
}

func parseOptionalTime(value sql.NullString, field string) (*time.Time, error) {
	if !value.Valid || value.String == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value.String)
	if err != nil {
		return nil, fmt.Errorf("parsing %s %q: %w", field, value.String, err)
	}
	return &parsed, nil
}

func encodeJSON(value any, field string) (sql.NullString, error) {
	if value == nil {
		return sql.NullString{}, nil
	}
	data, err := json.Marshal(value)
	if err != nil {
		return sql.NullString{}, fmt.Errorf("marshaling %s: %w", field, err)
	}
	if string(data) == "null" {
		return sql.NullString{}, nil
	}
	return sql.NullString{String: string(data), Valid: true}, nil
}

func decodeJSON(value sql.NullString, dst any, field string) error {
	if !value.Valid || value.String == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(value.String), dst); err != nil {
		return fmt.Errorf("parsing %s: %w", field, err)
	}
	return nil
}
