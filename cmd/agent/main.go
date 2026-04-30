package main

import (
	"fmt"
	"os"

	"github.com/TaconeoMental/certplane/config"
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
