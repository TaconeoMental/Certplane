package main

import (
	"context"
	"fmt"
	"os"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/agent"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var cfg config.ConfigFlag

	root := &cobra.Command{
		Use:           os.Args[0],
		Short:         "Certplane certificate agent",
		SilenceErrors: true,
		SilenceUsage:  true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	root.SetHelpCommand(&cobra.Command{
		Hidden: true,
	})

	root.PersistentFlags().Var(&cfg, "config", "config file path")
	if err := root.MarkPersistentFlagRequired("config"); err != nil {
		panic(err)
	}

	root.AddCommand(
		newEnrollCmd(&cfg),
		newRunCmd(&cfg),
	)

	return root
}

func newEnrollCmd(cfg *config.ConfigFlag) *cobra.Command {
	return &cobra.Command{
		Use:   "enroll",
		Short: "Bootstrap agent identity against the CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnroll(cmd.Context(), cfg.Path)
		},
	}
}

func newRunCmd(cfg *config.ConfigFlag) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run the agent renewal loop",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(cmd.Context(), cfg.Path)
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

func runRun(ctx context.Context, configPath string) error {
	_ = configPath
	return nil
}
