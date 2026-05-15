package main

import (
	"context"

	"github.com/TaconeoMental/certplane/internal/agent"
	"github.com/spf13/cobra"
)

func newEnrollCommand(state *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "enroll",
		Short: "Enroll this host and obtain an agent identity certificate",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnroll(cmd.Context(), state.configPath)
		},
	}
}

func runEnroll(ctx context.Context, configPath string) error {
	cfg, identityCA, err := loadAgentRuntime(configPath)
	if err != nil {
		return err
	}
	return agent.Enroll(ctx, cfg, identityCA)
}
