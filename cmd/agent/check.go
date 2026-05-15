package main

import (
	"github.com/TaconeoMental/certplane/internal/agent"
	"github.com/spf13/cobra"
)

func newCheckCommand(state *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Validate agent configuration and local files",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := loadAgentConfig(state.configPath)
			if err != nil {
				return err
			}
			return agent.Check(cfg)
		},
	}
}
