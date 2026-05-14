package audit

import "time"

type EventType string
type Decision string
type Severity string

const (
	SeverityInfo  Severity = "info"
	SeverityWarn  Severity = "warn"
	SeverityError Severity = "error"
)

const (
	EventBrokerStarted              EventType = "broker_started"
	EventPolicyLoaded               EventType = "policy_loaded"
	EventPolicyReloadFailed         EventType = "policy_reload_failed"
	EventCertificateRequestReceived EventType = "certificate_request_received"
	EventCertificateAuthorized      EventType = "certificate_authorized"
	EventCertificateDenied          EventType = "certificate_denied"
	EventCertificateCacheHit        EventType = "certificate_cache_hit"
	EventCertificateCacheMiss       EventType = "certificate_cache_miss"
	EventCertificateIssued          EventType = "certificate_issued"
	EventCertificateIssueFailed     EventType = "certificate_issue_failed"
)

const (
	DecisionAllow     Decision = "allow"
	DecisionDeny      Decision = "deny"
	DecisionIssue     Decision = "issue"
	DecisionCacheHit  Decision = "cache_hit"
	DecisionCacheMiss Decision = "cache_miss"
	DecisionError     Decision = "error"
)

const (
	ReasonOK                       = "ok"
	ReasonNoClientCertificate      = "no_client_certificate"
	ReasonInvalidClientCertificate = "invalid_client_certificate"
	ReasonUnknownIdentity          = "unknown_identity"
	ReasonProfileNotAllowed        = "profile_not_allowed"
	ReasonUnknownProfile           = "unknown_profile"
	ReasonInvalidRequest           = "invalid_request"
	ReasonInvalidCSR               = "invalid_csr"
	ReasonCSRNamesMismatch         = "csr_names_mismatch"
	ReasonRateLimited              = "rate_limited"
	ReasonCacheHit                 = "cache_hit"
	ReasonCacheMiss                = "cache_miss"
	ReasonIssuerFailed             = "issuer_failed"
)

// Most fields are optional because events are emitted at different stages of
// the request lifecycle.
type Event struct {
	EventID   string    `json:"event_id"`
	RequestID string    `json:"request_id"`
	Timestamp time.Time `json:"timestamp"`

	Type     EventType `json:"event_type"`
	Severity Severity  `json:"severity"`
	Decision Decision  `json:"decision"`

	Identity    string `json:"identity,omitempty"`
	ProfileName string `json:"profile_name,omitempty"`
	ProfileHash string `json:"profile_hash,omitempty"`
	PolicyHash  string `json:"policy_hash,omitempty"`

	ReasonCode string `json:"reason_code,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Error      string `json:"error,omitempty"`

	SourceIP  string `json:"source_ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`

	CSRSHA256          string   `json:"csr_sha256,omitempty"`
	CSRPublicKeySHA256 string   `json:"csr_public_key_sha256,omitempty"`
	CSRDNSNames        []string `json:"csr_dns_names,omitempty"`
	ExpectedDNSNames   []string `json:"expected_dns_names,omitempty"`

	IssuerName      string `json:"issuer_name,omitempty"`
	IssuerDirectory string `json:"issuer_directory,omitempty"`
	ACMEOrderURL    string `json:"acme_order_url,omitempty"`

	CertSerialNumber string     `json:"cert_serial_number,omitempty"`
	CertNotBefore    *time.Time `json:"cert_not_before,omitempty"`
	CertNotAfter     *time.Time `json:"cert_not_after,omitempty"`

	CacheResult string `json:"cache_result,omitempty"`

	// Reserved for small diagnostic details that do not deserve a first class
	// column yet.
	Metadata map[string]any `json:"metadata,omitempty"`
}
