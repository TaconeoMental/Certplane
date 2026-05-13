package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/pki"
)

type BrokerClient struct {
	baseURL string
	client  *http.Client
}

type issueRequest struct {
	Profile string `json:"profile"`
	CSRPEM  string `json:"csr_pem"`
}

type issueResponse struct {
	CertPEM          string `json:"cert_pem"`
	ChainPEM         string `json:"chain_pem"`
	FullChainPEM     string `json:"fullchain_pem"`
	LeafSerialNumber string `json:"serial_number"`
	NotBefore        string `json:"not_before"`
	NotAfter         string `json:"not_after"`
	Cache            string `json:"cache"`
}

func NewBrokerClient(cfg *config.AgentConfig) (*BrokerClient, error) {
	cert, err := tls.LoadX509KeyPair(cfg.Identity.Cert, cfg.Identity.Key)
	if err != nil {
		return nil, fmt.Errorf("loading identity keypair: %w", err)
	}
	caData, err := os.ReadFile(cfg.Broker.ServerCABundle)
	if err != nil {
		return nil, fmt.Errorf("reading broker server CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("broker server CA bundle contains no certificates")
	}

	// horrendo....
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12},
	}
	return &BrokerClient{baseURL: cfg.Broker.URL, client: &http.Client{Timeout: cfg.Broker.Timeout, Transport: transport}}, nil
}

func (c *BrokerClient) Issue(ctx context.Context, profile string, csrPEM []byte) (*pki.Bundle, error) {
	payload, err := json.Marshal(issueRequest{Profile: profile, CSRPEM: string(csrPEM)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/certificates", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling broker: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("reading broker response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("broker returned HTTP %d: %s", resp.StatusCode, string(bytes.TrimSpace(body)))
	}
	var out issueResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parsing broker response: %w", err)
	}
	notBefore, err := time.Parse(time.RFC3339, out.NotBefore)
	if err != nil {
		return nil, fmt.Errorf("parsing not_before: %w", err)
	}
	notAfter, err := time.Parse(time.RFC3339, out.NotAfter)
	if err != nil {
		return nil, fmt.Errorf("parsing not_after: %w", err)
	}
	return &pki.Bundle{
		CertPEM:          []byte(out.CertPEM),
		ChainPEM:         []byte(out.ChainPEM),
		FullChainPEM:     []byte(out.FullChainPEM),
		LeafSerialNumber: out.LeafSerialNumber,
		NotBefore:        notBefore,
		NotAfter:         notAfter}, nil
}
