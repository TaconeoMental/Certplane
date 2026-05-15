package main

import (
	"os"

	"github.com/spf13/cobra"
)

type cliOptions struct {
	configPath string
}

func newRootCommand() *cobra.Command {
	opts := &cliOptions{}
	cmd := &cobra.Command{
		Use:           os.Args[0],
		Short:         "Certplane broker",
		SilenceErrors: true,
		SilenceUsage:  true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	cmd.SetHelpCommand(&cobra.Command{
		Hidden: true,
	})

	cmd.PersistentFlags().StringVarP(
		&opts.configPath,
		"config",
		"c",
		"",
		"YAML config file path",
	)
	if err := cmd.MarkPersistentFlagRequired("config"); err != nil {
		panic(err)
	}

	cmd.AddCommand(
		newServeCommand(opts),
		newPolicyCommand(),
		newCertsCommand(opts),
		newAuditCommand(opts),
	)

	return cmd
}
