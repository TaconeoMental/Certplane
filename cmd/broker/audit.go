package main

import (
	"context"
	"io"

	"github.com/spf13/cobra"
)

func newAuditCommand(opts *cliOptions) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit utilities",
	}
	cmd.AddCommand(newAuditTailCommand(opts))
	return cmd
}

func newAuditTailCommand(opts *cliOptions) *cobra.Command {
	var limit int

	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Write recent audit events as JSON lines",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuditTail(cmd.Context(), opts.configPath, limit, cmd.OutOrStdout())
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 200, "maximum number of audit events to print")
	return cmd
}

func runAuditTail(ctx context.Context, configPath string, limit int, w io.Writer) error {
	cfg, err := loadBrokerConfig(configPath)
	if err != nil {
		return err
	}

	brokerStore, err := openBrokerStore(cfg)
	if err != nil {
		return err
	}
	defer brokerStore.Close()

	return brokerStore.WriteAuditEvents(ctx, w, limit)
}
