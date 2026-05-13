package agent

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/ca"
	"github.com/TaconeoMental/certplane/internal/fileutil"
	"github.com/TaconeoMental/certplane/internal/pki"
)

func RenewIdentityIfNeeded(ctx context.Context, cfg *config.AgentConfig, identityCA ca.IdentityCA) error {
	certData, err := os.ReadFile(cfg.Identity.Cert)
	if err != nil {
		return fmt.Errorf("reading identity cert: %w", err)
	}
	keyData, err := os.ReadFile(cfg.Identity.Key)
	if err != nil {
		return fmt.Errorf("reading identity key: %w", err)
	}
	rootCAData, err := os.ReadFile(cfg.Identity.IssuerCABundle)
	if err != nil {
		return fmt.Errorf("reading identity issuer CA bundle: %w", err)
	}
	cert, err := pki.ParseCertificatePEM(certData)
	if err != nil {
		return fmt.Errorf("parsing identity cert: %w", err)
	}
	if pki.IsExpired(cert) {
		return fmt.Errorf("identity cert expired at %s, re-enroll required", cert.NotAfter.Format(time.RFC3339))
	}

	expiresIn := time.Until(cert.NotAfter)

	if !pki.ExpiresWithin(cert, cfg.Identity.RenewBefore) {
		if pki.ExpiresWithin(cert, cfg.Identity.WarnBefore) {
			slog.Warn(
				"identity certificate is close to expiration",
				"expires_in", expiresIn.Round(time.Minute).String(),
				"not_after", cert.NotAfter.Format(time.RFC3339),
			)
		}

		return nil
	}

	slog.Info(
		"identity certificate is inside renewal window",
		"expires_in", expiresIn.Round(time.Minute).String(),
		"not_after", cert.NotAfter.Format(time.RFC3339),
	)

	renewed, err := identityCA.Renew(ctx, ca.RenewalRequest{
		CertPEM:     certData,
		KeyPEM:      keyData,
		IssuerCAPEM: rootCAData,
	})
	if err != nil {
		return fmt.Errorf("renewing identity cert: %w", err)
	}
	if err := fileutil.WriteFileAtomic(cfg.Identity.Cert, renewed.CertPEM, 0o644); err != nil {
		return fmt.Errorf("writing renewed identity cert: %w", err)
	}
	return nil
}
