package broker

import (
	"crypto/x509"
	"net/http"
	"time"

	"github.com/TaconeoMental/certplane/internal/broker/policy"
	"github.com/TaconeoMental/certplane/internal/pki"
)

type issueRequest struct {
	Profile string `json:"profile"`
	CSRPEM  string `json:"csr_pem"`
}

type issueResponse struct {
	CertPEM      string `json:"cert_pem"`
	ChainPEM     string `json:"chain_pem"`
	FullChainPEM string `json:"fullchain_pem"`
	SerialNumber string `json:"serial_number"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	Cache        string `json:"cache"`
}

type issuedResult struct {
	bundle *pki.Bundle
	cache  string
}

type certificateRequestContext struct {
	RequestID string
	Request   *http.Request

	Identity    string
	ProfileName string

	Policy  *policy.CompiledPolicy
	Profile *policy.CompiledProfile

	CSR         *x509.CertificateRequest
	CSRPEM      []byte
	PublicKeyFP string
}

func newIssueResponse(result issuedResult) issueResponse {
	bundle := result.bundle
	return issueResponse{
		CertPEM:      string(bundle.CertPEM),
		ChainPEM:     string(bundle.ChainPEM),
		FullChainPEM: string(bundle.FullChainPEM),
		SerialNumber: bundle.LeafSerialNumber,
		NotBefore:    bundle.NotBefore.Format(time.RFC3339),
		NotAfter:     bundle.NotAfter.Format(time.RFC3339),
		Cache:        result.cache,
	}
}
