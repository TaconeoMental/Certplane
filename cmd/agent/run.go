package main

import (
	"context"

	"github.com/spf13/cobra"
)

func newRunCommand(state *cliState) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run the agent renewal loop",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(cmd.Context(), state.configPath)
		},
	}
}

func runRun(ctx context.Context, configPath string) error {
	cfg, identityCA, err := loadAgentRuntime(configPath)
	_, _ = cfg, identityCA
	if err != nil {
		return err
	}

	//return agent.Run(ctx, cfg, identityCA)
	return nil
}
