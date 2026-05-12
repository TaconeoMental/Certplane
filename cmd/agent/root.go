package main

import (
	"os"

	"github.com/spf13/cobra"
)


type cliState struct {
	configPath string
}


func newRootCommand() *cobra.Command {
	state := &cliState{}
	cmd := &cobra.Command{
		Use:           os.Args[0],
		Short:         "Certplane agent",
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
		&state.configPath,
		"config",
		"c",
		"",
		"YAML config file path",
	)
	if err := cmd.MarkPersistentFlagRequired("config"); err != nil {
		panic(err)
	}

	cmd.AddCommand(
		newEnrollCommand(state),
		newRunCommand(state),
	)

	return cmd
}
