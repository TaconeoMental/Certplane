package main

import (
	"context"
	"fmt"
	"os"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/agent"
	"github.com/TaconeoMental/certplane/internal/fileutil"
	"github.com/TaconeoMental/certplane/internal/pki"
	"github.com/spf13/cobra"
)

func newRunCmd(cfg *config.ConfigFlag) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run the agent renewal loop",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(cmd.Context(), cfg.Path)
		},
	}
}

func runRun(ctx context.Context, configPath string) error {
	cfg, err := config.LoadAgent(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	if !fileutil.FileExists(cfg.Identity.Cert) {
		return fmt.Errorf("identity cert not found at %s, run enroll first", cfg.Identity.Cert)
	}

	identityCA, err := resolveIdentityCA(cfg)
	if err != nil {
		return fmt.Errorf("initializing identity CA: %w", err)
	}

	if err := agent.RenewIdentityIfNeeded(ctx, cfg, identityCA); err != nil {
		return fmt.Errorf("renewing identity: %w", err)
	}

	for i := range cfg.Certificates {
		certCfg := &cfg.Certificates[i]

		if fileutil.FileExists(certCfg.Cert) {
			certData, err := os.ReadFile(certCfg.Cert)
			if err != nil {
				return fmt.Errorf("reading cert for profile %s: %w", certCfg.Profile, err)
			}
			cert, err := pki.ParseCertificate(certData)
			if err != nil {
				return fmt.Errorf("parsing cert for profile %s: %w", certCfg.Profile, err)
			}
			if !pki.ExpiresWithin(cert, certCfg.RenewBefore) {
				continue
			}
		}

		// TODO: request cert, install bundle
	}

	return nil
}
