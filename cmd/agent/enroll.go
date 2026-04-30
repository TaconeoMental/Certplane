package main

import (
	"context"
	"fmt"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/agent"
	"github.com/spf13/cobra"
)

func newEnrollCmd(cfg *config.ConfigFlag) *cobra.Command {
	return &cobra.Command{
		Use:   "enroll",
		Short: "Bootstrap agent identity against the CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnroll(cmd.Context(), cfg.Path)
		},
	}
}

func runEnroll(ctx context.Context, configPath string) error {
	cfg, err := config.LoadAgent(configPath)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	identityCA, err := resolveIdentityCA(cfg)
	if err != nil {
		return fmt.Errorf("initializing identity CA: %w", err)
	}
	return agent.Enroll(ctx, cfg, identityCA)
}
