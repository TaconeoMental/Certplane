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

	tokenData, err := os.ReadFile(cfg.Identity.BootstrapToken)
	if err != nil {
		return fmt.Errorf("reading bootstrap token %q: %w", cfg.Identity.BootstrapToken, err)
	}
	token := strings.TrimSpace(string(tokenData))
	if token == "" {
		return fmt.Errorf("bootstrap token is empty")
	}
	// TODO...
	return nil
}
