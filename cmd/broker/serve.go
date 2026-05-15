package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/TaconeoMental/certplane/internal/broker"
	"github.com/TaconeoMental/certplane/internal/broker/policy"
	"github.com/spf13/cobra"
)

func newServeCommand(opts *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the broker HTTPS/mTLS API",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), opts.configPath)
		},
	}
}

func runServe(ctx context.Context, configPath string) error {
	cfg, err := loadBrokerConfig(configPath)
	if err != nil {
		return err
	}

	policyManager, err := policy.NewManager(cfg.Policy.Path)
	if err != nil {
		return fmt.Errorf("loading policy: %w", err)
	}

	secretProvider, err := buildSecretsProvider(cfg)
	if err != nil {
		return err
	}

	brokerStore, err := openBrokerStore(cfg)
	if err != nil {
		return err
	}
	defer brokerStore.Close()

	certIssuer, err := buildIssuer(cfg, secretProvider)
	if err != nil {
		return err
	}

	if cfg.Policy.Watch {
		go policyManager.Watch(ctx)
	}

	auditRecorder := buildAuditRecorder(cfg, brokerStore)
	server := broker.NewServer(cfg, policyManager, brokerStore, certIssuer, auditRecorder, slog.Default())
	return server.ListenAndServe(ctx)
}
