package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/ca"
	"github.com/TaconeoMental/certplane/internal/fileutil"
	"github.com/TaconeoMental/certplane/internal/pki"
)

func Enroll(ctx context.Context, cfg *config.AgentConfig, identityCA ca.IdentityCA) error {
	lockPath := filepath.Join(cfg.StateDir, "agent.lock")
	lock, err := fileutil.AcquireLock(lockPath)
	if err != nil {
		return err
	}
	defer lock.Release()

	exists, err := fileutil.FileExists(cfg.Identity.Cert)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("identity cert already exists at %s", cfg.Identity.Cert)
	}

	_, _, err = pki.EnsureECDSAPrivateKey(cfg.Identity.Key)
	if err != nil {
		return fmt.Errorf("ensuring identity key: %w", err)
	}
	keyData, err := os.ReadFile(cfg.Identity.Key)
	if err != nil {
		return fmt.Errorf("reading persisted identity key: %w", err)
	}
	key, err := pki.ParsePrivateKeyPEM(keyData)
	if err != nil {
		return fmt.Errorf("parsing persisted identity key: %w", err)
	}

	tokenData, err := os.ReadFile(cfg.Identity.BootstrapToken)
	if err != nil {
		return fmt.Errorf("reading bootstrap token %q: %w", cfg.Identity.BootstrapToken, err)
	}
	token := strings.TrimSpace(string(tokenData))
	if token == "" {
		return fmt.Errorf("bootstrap token is empty")
	}

	csrPEM, err := pki.GenerateIdentityCSR(key, cfg.Identity.Name)
	if err != nil {
		return fmt.Errorf("generating identity CSR: %w", err)
	}

	identity, err := identityCA.Enroll(ctx, ca.EnrollmentRequest{CSRPEM: csrPEM, Token: token})
	if err != nil {
		return fmt.Errorf("enrolling with identity CA: %w", err)
	}
	if err := fileutil.WriteFileAtomic(cfg.Identity.Cert, identity.CertPEM, 0o644); err != nil {
		return fmt.Errorf("writing identity cert: %w", err)
	}
	if err := os.Remove(cfg.Identity.BootstrapToken); err != nil {
		return fmt.Errorf("removing bootstrap token: %w", err)
	}
	return nil
}
