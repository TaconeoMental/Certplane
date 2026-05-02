package agent

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/ca"
	"github.com/TaconeoMental/certplane/internal/pki"
)

func RenewIdentityIfNeeded(ctx context.Context, cfg *config.AgentConfig, identityCA ca.IdentityCA) error {
	certData, err := os.ReadFile(cfg.Identity.Cert)
	if err != nil {
		return fmt.Errorf("reading identity cert: %w", err)
	}

	keyData, err := os.ReadFile(cfg.Identity.Cert)
	if err != nil {
		return fmt.Errorf("reading identity key: %w", err)
	}

	rootCAData, err := os.ReadFile(cfg.Broker.ServerCA)
	if err != nil {
		return fmt.Errorf("reading root CA: %w", err)
	}

	cert, err := pki.ParseCertificate(certData)
	if err != nil {
		return fmt.Errorf("parsing identity cert: %w", err)
	}

	if pki.IsExpired(cert) {
		return fmt.Errorf("identity cert expired at %s, need to re enroll", cert.NotAfter.Format(time.RFC3339))
	}

	if !pki.ExpiresWithin(cert, cfg.Identity.RenewBefore) {
		return nil
	}

	if pki.ExpiresWithin(cert, cfg.Identity.WarnBefore) {
		fmt.Fprintf(os.Stderr, "WARNING: identity cert expires in %s",
			time.Until(cert.NotAfter).Round(time.Minute))
	}

	renewed, err := identityCA.Renew(ctx, certData, keyData, rootCAData)
	if err != nil {
		return fmt.Errorf("renewing identity cert: %w", err)
	}

	if err := os.WriteFile(cfg.Identity.Cert, renewed.CertPEM, 0644); err != nil {
		return fmt.Errorf("writing renewed identity cert: %w", err)
	}

	return nil
}
