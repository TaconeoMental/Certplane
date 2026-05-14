package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/TaconeoMental/certplane/internal/broker/audit"
)

func (s *Server) HTTPServer() (*http.Server, error) {
	agentCAPool, err := loadCertPool(s.cfg.Server.MTLS.AgentCABundle)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /readyz", s.readyz)
	mux.HandleFunc("POST /v1/certificates", s.issueCertificate)

	return &http.Server{
		Addr:              s.cfg.Server.Address,
		Handler:           mux,
		ReadHeaderTimeout: s.cfg.Server.ReadHeaderTimeout,
		ReadTimeout:       s.cfg.Server.ReadTimeout,
		WriteTimeout:      s.cfg.Server.WriteTimeout,
		IdleTimeout:       s.cfg.Server.IdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion: tlsMinVersion(s.cfg.Server.TLS.MinVersion),
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  agentCAPool,
		},
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	httpServer, err := s.HTTPServer()
	if err != nil {
		return err
	}

	_ = s.record(ctx, audit.Event{Type: audit.EventBrokerStarted, Severity: audit.SeverityInfo, Decision: audit.DecisionAllow, ReasonCode: audit.ReasonOK})

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	s.logger.Info("certplane-broker listening", "address", s.cfg.Server.Address)
	if err := httpServer.ListenAndServeTLS(s.cfg.Server.TLS.Cert, s.cfg.Server.TLS.Key); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if s.policy.Current() == nil {
		http.Error(w, "policy not loaded", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready\n"))
}

func tlsMinVersion(version string) uint16 {
	if version == "1.3" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

func loadCertPool(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading CA bundle %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("CA bundle %q contains no certificates", path)
	}
	return pool, nil
}
