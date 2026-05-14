package store

import "strings"

var certificateCacheColumns = []string{
	"identity",
	"profile_name",
	"profile_hash",
	"public_key_sha256",
	"issuer_name",
	"issuer_directory",
	"issuer_account_key_id",
	"cert_pem",
	"chain_pem",
	"fullchain_pem",
	"serial_number",
	"not_before",
	"not_after",
	"created_at",
	"updated_at",
}

var auditEventColumns = []string{
	"event_id",
	"request_id",
	"timestamp",
	"event_type",
	"severity",
	"decision",
	"identity",
	"profile_name",
	"profile_hash",
	"policy_hash",
	"reason_code",
	"reason",
	"error",
	"source_ip",
	"user_agent",
	"csr_sha256",
	"csr_public_key_sha256",
	"csr_dns_names_json",
	"expected_dns_names_json",
	"issuer_name",
	"issuer_directory",
	"acme_order_url",
	"cert_serial_number",
	"cert_not_before",
	"cert_not_after",
	"cache_result",
	"metadata_json",
}

func columnList(columns []string) string {
	return strings.Join(columns, ", ")
}

