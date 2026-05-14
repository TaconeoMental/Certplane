package main

import (
	"context"
	"fmt"

	"github.com/TaconeoMental/certplane/internal/broker/policy"
	"github.com/spf13/cobra"
)

func newServeCommand(state *cliState) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the broker HTTPS/mTLS API",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServe(cmd.Context(), state.configPath)
		},
	}
}

func runServe(ctx context.Context, configPath string) error {
	cfg, err := loadBrokerConfig(configPath)
	if err != nil {
		return err
	}

	return nil

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
	_ = secretProvider
	_= policyManager
	// TODO
	return nil
}
