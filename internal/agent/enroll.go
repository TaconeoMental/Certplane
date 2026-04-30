package agent

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/ca"
	"github.com/TaconeoMental/certplane/internal/fileutil"
	"github.com/TaconeoMental/certplane/internal/pki"
)

func Enroll(ctx context.Context, cfg *config.AgentConfig, identityCA ca.IdentityCA) error {
	if fileutil.FileExists(cfg.Identity.Cert) {
		return fmt.Errorf("identity cert already exists")
	}
	if !fileutil.FileExists(cfg.Identity.BootstrapToken) {
		return fmt.Errorf("%s does not exist", cfg.Identity.BootstrapToken)
	}

	tokenData, _ := os.ReadFile(cfg.Identity.BootstrapToken)
	token := strings.TrimSpace(string(tokenData))

	keyPair, err := pki.NewECDSAKeyPair()
	if err != nil {
		return fmt.Errorf("generating keypair: %w", err)
	}

	csrPEM, err := pki.GenerateCSR(keyPair.PrivateKey, cfg.Identity.CN)
	if err != nil {
		return fmt.Errorf("generating CSR: %w", err)
	}

	csr, err := pki.ParseCSR(csrPEM)
	if err != nil {
		return fmt.Errorf("parsing CSR: %w", err)
	}

	identity, err := identityCA.Enroll(ctx, &ca.EnrollmentRequest{
		CSR:   csr,
		Token: token,
	})
	if err != nil {
		return fmt.Errorf("enrolling with identity CA: %w", err)
	}

	if err := fileutil.WriteFile(cfg.Identity.Key, keyPair.KeyPEM, 0600); err != nil {
		return fmt.Errorf("writing identity key: %w", err)
	}

	if err := fileutil.WriteFile(cfg.Identity.Cert, identity.CertPEM, 0644); err != nil {
		return fmt.Errorf("writing identity cert: %w", err)
	}

	if err := os.Remove(cfg.Identity.BootstrapToken); err != nil {
		return fmt.Errorf("removing bootstrap token: %w", err)
	}

	return nil
}
