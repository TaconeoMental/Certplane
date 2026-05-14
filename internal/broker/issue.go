package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/TaconeoMental/certplane/internal/broker/audit"
	"github.com/TaconeoMental/certplane/internal/broker/authn"
	"github.com/TaconeoMental/certplane/internal/broker/issuer"
	"github.com/TaconeoMental/certplane/internal/broker/policy"
	"github.com/TaconeoMental/certplane/internal/broker/store"
	"github.com/TaconeoMental/certplane/internal/pki"
)

const maxIssueRequestBodyBytes = 64 * 1024

func (s *Server) issueCertificate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	reqCtx := &certificateRequestContext{
		RequestID: audit.NewID("req_"),
		Request:   r,
	}

	if !s.authenticateIssueRequest(ctx, w, reqCtx) {
		return
	}
	if !s.parseIssueRequest(ctx, w, reqCtx) {
		return
	}
	if !s.authorizeIssueRequest(ctx, w, reqCtx) {
		return
	}
	if !s.attachPublicKeyFingerprint(ctx, w, reqCtx) {
		return
	}
	if !s.recordAuthorizedIssue(ctx, w, reqCtx) {
		return
	}
	if !s.checkIssueRateLimit(ctx, w, reqCtx) {
		return
	}

	key := s.cacheKey(reqCtx.Identity, reqCtx.ProfileName, reqCtx.Profile, reqCtx.PublicKeyFP)
	issued, ok := s.issueOrLoadWithSingleflight(ctx, w, reqCtx, key)
	if !ok {
		return
	}
	if !s.recordIssuedResult(ctx, w, reqCtx, issued) {
		return
	}

	writeJSON(w, http.StatusOK, newIssueResponse(issued))
}

func (s *Server) authenticateIssueRequest(ctx context.Context, w http.ResponseWriter, reqCtx *certificateRequestContext) bool {
	identity, err := authn.IdentityFromRequest(reqCtx.Request)
	if err != nil {
		event := reqCtx.auditEvent(s, audit.EventCertificateDenied, audit.SeverityWarn, audit.DecisionDeny, audit.ReasonInvalidClientCertificate, err)
		_ = s.record(ctx, event)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}

	reqCtx.Identity = identity
	event := reqCtx.auditEvent(s, audit.EventCertificateRequestReceived, audit.SeverityInfo, audit.DecisionAllow, audit.ReasonOK, nil)
	_ = s.record(ctx, event)
	return true
}

func (s *Server) parseIssueRequest(ctx context.Context, w http.ResponseWriter, reqCtx *certificateRequestContext) bool {
	reqCtx.Request.Body = http.MaxBytesReader(w, reqCtx.Request.Body, maxIssueRequestBodyBytes)
	body, err := io.ReadAll(reqCtx.Request.Body)
	if err != nil {
		s.denyBadRequest(ctx, w, reqCtx, audit.ReasonInvalidRequest, err, "invalid request")
		return false
	}

	var req issueRequest
	if err := json.Unmarshal(body, &req); err != nil {
		s.denyBadRequest(ctx, w, reqCtx, audit.ReasonInvalidRequest, err, "invalid request")
		return false
	}
	if req.Profile == "" || req.CSRPEM == "" {
		reqCtx.ProfileName = req.Profile
		err := fmt.Errorf("profile and csr_pem are required")
		s.denyBadRequest(ctx, w, reqCtx, audit.ReasonInvalidRequest, err, "invalid request")
		return false
	}

	reqCtx.ProfileName = req.Profile
	reqCtx.CSRPEM = []byte(req.CSRPEM)

	csr, err := pki.ParseCSRPEM(reqCtx.CSRPEM)
	if err != nil {
		s.denyBadRequest(ctx, w, reqCtx, audit.ReasonInvalidCSR, err, "invalid csr")
		return false
	}
	reqCtx.CSR = csr
	return true
}

func (s *Server) authorizeIssueRequest(ctx context.Context, w http.ResponseWriter, reqCtx *certificateRequestContext) bool {
	pol := s.policy.Current()
	if pol == nil {
		err := fmt.Errorf("policy not loaded")
		event := reqCtx.auditEvent(s, audit.EventCertificateIssueFailed, audit.SeverityError, audit.DecisionError, audit.ReasonIssuerFailed, err)
		_ = s.record(ctx, event)
		writeError(w, http.StatusServiceUnavailable, "policy not loaded")
		return false
	}
	reqCtx.Policy = pol

	profile, err := pol.Authorize(reqCtx.Identity, reqCtx.ProfileName, reqCtx.CSR)
	if err == nil {
		reqCtx.Profile = profile
		return true
	}
	if profile != nil {
		reqCtx.Profile = profile
	}

	event := reqCtx.auditEvent(s, audit.EventCertificateDenied, audit.SeverityWarn, audit.DecisionDeny, auditReasonForPolicyError(err), err)
	_ = s.record(ctx, event)
	writeError(w, http.StatusForbidden, "forbidden")
	return false
}

func (s *Server) attachPublicKeyFingerprint(ctx context.Context, w http.ResponseWriter, reqCtx *certificateRequestContext) bool {
	fingerprint, err := pki.PublicKeyFingerprint(reqCtx.CSR.PublicKey)
	if err != nil {
		s.denyBadRequest(ctx, w, reqCtx, audit.ReasonInvalidCSR, err, "invalid csr")
		return false
	}
	reqCtx.PublicKeyFP = fingerprint
	return true
}

func (s *Server) recordAuthorizedIssue(ctx context.Context, w http.ResponseWriter, reqCtx *certificateRequestContext) bool {
	event := reqCtx.auditEvent(s, audit.EventCertificateAuthorized, audit.SeverityInfo, audit.DecisionAllow, audit.ReasonOK, nil)
	if err := s.auditBarrier(ctx, event); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit unavailable")
		return false
	}
	return true
}

func (s *Server) checkIssueRateLimit(ctx context.Context, w http.ResponseWriter, reqCtx *certificateRequestContext) bool {
	if err := s.rateLimiter.Allow(reqCtx.Identity, reqCtx.ProfileName); err != nil {
		event := reqCtx.auditEvent(s, audit.EventCertificateDenied, audit.SeverityWarn, audit.DecisionDeny, audit.ReasonRateLimited, err)
		_ = s.record(ctx, event)
		writeError(w, http.StatusTooManyRequests, "rate limited")
		return false
	}
	return true
}

func (s *Server) issueOrLoadWithSingleflight(ctx context.Context, w http.ResponseWriter, reqCtx *certificateRequestContext, key store.CertificateCacheKey) (issuedResult, bool) {
	result, err, _ := s.flightGroup.Do(key.String(), func() (any, error) {
		return s.issueOrLoad(ctx, key, reqCtx.Profile, reqCtx.CSRPEM)
	})
	if err != nil {
		event := reqCtx.auditEvent(s, audit.EventCertificateIssueFailed, audit.SeverityError, audit.DecisionError, audit.ReasonIssuerFailed, err)
		_ = s.record(ctx, event)
		writeError(w, http.StatusBadGateway, "issuance failed")
		return issuedResult{}, false
	}

	issued, ok := result.(issuedResult)
	if !ok {
		err := fmt.Errorf("internal singleflight result has unexpected type %T", result)
		event := reqCtx.auditEvent(s, audit.EventCertificateIssueFailed, audit.SeverityError, audit.DecisionError, audit.ReasonIssuerFailed, err)
		_ = s.record(ctx, event)
		writeError(w, http.StatusInternalServerError, "internal error")
		return issuedResult{}, false
	}

	return issued, true
}

func (s *Server) recordIssuedResult(ctx context.Context, w http.ResponseWriter, reqCtx *certificateRequestContext, issued issuedResult) bool {
	event := reqCtx.issuedEvent(s, issued)
	if err := s.auditBarrier(ctx, event); err != nil {
		writeError(w, http.StatusServiceUnavailable, "audit unavailable")
		return false
	}
	return true
}

func (s *Server) issueOrLoad(ctx context.Context, key store.CertificateCacheKey, profile *policy.CompiledProfile, csrPEM []byte) (issuedResult, error) {
	bundle, err := s.store.GetValidCertificate(ctx, key, profile.RenewBefore)
	if err == nil {
		return issuedResult{bundle: bundle, cache: "hit"}, nil
	}
	if !errors.Is(err, store.ErrCacheMiss) {
		return issuedResult{}, err
	}

	bundle, err = s.issuer.Issue(ctx, issuer.IssueRequest{
		ProfileName:         profile.Name,
		DNSNames:            profile.DNSNames,
		CSRPEM:              csrPEM,
		ACMEChallenge:       profile.ACME.Challenge,
		ACMECredentialsName: profile.ACME.Credentials,
	})
	if err != nil {
		return issuedResult{}, err
	}
	if err := s.store.PutCertificate(ctx, key, bundle); err != nil {
		return issuedResult{}, err
	}
	return issuedResult{bundle: bundle, cache: "miss"}, nil
}

func (s *Server) cacheKey(identity, profileName string, profile *policy.CompiledProfile, publicKeyFP string) store.CertificateCacheKey {
	return store.CertificateCacheKey{
		Identity:           identity,
		ProfileName:        profileName,
		ProfileHash:        profile.Hash,
		PublicKeySHA256:    publicKeyFP,
		IssuerName:         s.issuer.Name(),
		IssuerDirectory:    s.issuer.Directory(),
		IssuerAccountKeyID: s.issuer.AccountKeyID(),
	}
}

func (s *Server) denyBadRequest(ctx context.Context, w http.ResponseWriter, reqCtx *certificateRequestContext, reason string, err error, message string) {
	event := reqCtx.auditEvent(s, audit.EventCertificateDenied, audit.SeverityWarn, audit.DecisionDeny, reason, err)
	_ = s.record(ctx, event)
	writeError(w, http.StatusBadRequest, message)
}

func auditReasonForPolicyError(err error) string {
	switch {
	case errors.Is(err, policy.ErrUnknownIdentity):
		return audit.ReasonUnknownIdentity
	case errors.Is(err, policy.ErrUnknownProfile):
		return audit.ReasonUnknownProfile
	case errors.Is(err, policy.ErrCSRNamesMismatch):
		return audit.ReasonCSRNamesMismatch
	case errors.Is(err, policy.ErrInvalidCSR):
		return audit.ReasonInvalidCSR
	case errors.Is(err, policy.ErrProfileNotAllowed):
		return audit.ReasonProfileNotAllowed
	default:
		return audit.ReasonProfileNotAllowed
	}
}
