package main

import (
	"context"
	"encoding/json"
	"io"

	"github.com/spf13/cobra"
)

func newCertsCommand(opts *cliOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "certs",
		Short: "Certificate cache utilities",
	}
	cmd.AddCommand(newCertsListCommand(opts))
	return cmd
}

func newCertsListCommand(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List cached certificate bundles",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCertsList(cmd.Context(), opts.configPath, cmd.OutOrStdout())
		},
	}
}

func runCertsList(ctx context.Context, configPath string, w io.Writer) error {
	cfg, err := loadBrokerConfig(configPath)
	if err != nil {
		return err
	}

	brokerStore, err := openBrokerStore(cfg)
	if err != nil {
		return err
	}
	defer brokerStore.Close()

	entries, err := brokerStore.List(ctx)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(entries)
}
