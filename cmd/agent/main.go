package main

import (
	"os"

	"github.com/TaconeoMental/certplane/config"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var cfg config.ConfigFlag

	root := &cobra.Command{
		Use:   os.Args[0],
		Short: "Certplane certificate agent",
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	root.SetHelpCommand(&cobra.Command{
		Hidden: true,
	})

	root.PersistentFlags().Var(&cfg, "config", "config file path")
	root.MarkPersistentFlagRequired("config")

	root.AddCommand(
		newEnrollCmd(&cfg.Path),
		newRunCmd(&cfg.Path),
	)

	return root
}

func newEnrollCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "enroll",
		Short: "Bootstrap agent identity against the CA",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEnroll(*configPath)
		},
	}
}

func newRunCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Run the agent renewal loop",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(*configPath)
		},
	}
}

func runEnroll(configPath string) error {
	_ = configPath
	return nil
}

func runRun(configPath string) error {
	_ = configPath
	return nil
}
