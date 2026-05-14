package broker

import (
	"context"
	"net/http"
	"time"

	"github.com/TaconeoMental/certplane/internal/broker/audit"
	"github.com/TaconeoMental/certplane/internal/dnsname"
	"github.com/TaconeoMental/certplane/internal/pki"
)

type auditEventBase struct {
	RequestID string
	Type      audit.EventType
	Severity  audit.Severity
	Decision  audit.Decision
	Reason    string
	Identity  string
	Profile   string
	Error     error
	Request   *http.Request
}

func newAuditEvent(base auditEventBase) audit.Event {
	event := audit.Event{
		EventID:     audit.NewID("evt_"),
		RequestID:   base.RequestID,
		Timestamp:   time.Now().UTC(),
		Type:        base.Type,
		Severity:    base.Severity,
		Decision:    base.Decision,
		ReasonCode:  base.Reason,
		Identity:    base.Identity,
		ProfileName: base.Profile,
	}
	if base.Error != nil {
		event.Reason = base.Error.Error()
		event.Error = base.Error.Error()
	}
	if base.Request != nil {
		event.SourceIP = sourceIP(base.Request)
		event.UserAgent = base.Request.UserAgent()
	}
	return event
}

func (c *certificateRequestContext) auditEvent(s *Server, typ audit.EventType, severity audit.Severity, decision audit.Decision, reasonCode string, err error) audit.Event {
	event := newAuditEvent(auditEventBase{
		RequestID: c.RequestID,
		Type:      typ,
		Severity:  severity,
		Decision:  decision,
		Reason:    reasonCode,
		Identity:  c.Identity,
		Profile:   c.ProfileName,
		Error:     err,
		Request:   c.Request,
	})

	if c.Policy != nil {
		event.PolicyHash = c.Policy.Hash
	}
	if c.Profile != nil {
		event.ProfileHash = c.Profile.Hash
		event.ExpectedDNSNames = append([]string(nil), c.Profile.DNSNames...)
	}
	if len(c.CSRPEM) > 0 {
		event.CSRSHA256 = pki.CSRFingerprint(c.CSRPEM)
	}
	if c.PublicKeyFP != "" {
		event.CSRPublicKeySHA256 = c.PublicKeyFP
	}
	if c.CSR != nil {
		names, canonErr := dnsname.CanonicalList(c.CSR.DNSNames)
		if canonErr != nil {
			event.Metadata = withMetadata(event.Metadata, "csr_dns_names_error", canonErr.Error())
		} else {
			event.CSRDNSNames = names
		}
	}

	return event
}

func (c *certificateRequestContext) issuedEvent(s *Server, issued issuedResult) audit.Event {
	eventType := audit.EventCertificateIssued
	decision := audit.DecisionIssue
	reason := audit.ReasonCacheMiss
	if issued.cache == "hit" {
		eventType = audit.EventCertificateCacheHit
		decision = audit.DecisionCacheHit
		reason = audit.ReasonCacheHit
	}

	event := c.auditEvent(s, eventType, audit.SeverityInfo, decision, reason, nil)
	event.IssuerName = s.issuer.Name()
	event.IssuerDirectory = s.issuer.Directory()
	event.CertSerialNumber = issued.bundle.LeafSerialNumber
	notBefore := issued.bundle.NotBefore
	notAfter := issued.bundle.NotAfter
	event.CertNotBefore = &notBefore
	event.CertNotAfter = &notAfter
	event.CacheResult = issued.cache
	return event
}

func (s *Server) record(ctx context.Context, event audit.Event) error {
	event = normalizeAuditEvent(event)
	if s.audit == nil {
		return nil
	}
	if err := s.audit.Record(ctx, event); err != nil {
		s.logger.Warn("audit recording failed", "error", err)
		return err
	}
	return nil
}

func (s *Server) auditBarrier(ctx context.Context, event audit.Event) error {
	if err := s.record(ctx, event); err != nil && s.failureMode == "fail_closed" {
		return err
	}
	return nil
}

func normalizeAuditEvent(event audit.Event) audit.Event {
	if event.EventID == "" {
		event.EventID = audit.NewID("evt_")
	}
	if event.RequestID == "" {
		event.RequestID = audit.NewID("req_")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	return event
}

func withMetadata(metadata map[string]any, key string, value any) map[string]any {
	if metadata == nil {
		metadata = make(map[string]any, 1)
	}
	metadata[key] = value
	return metadata
}
