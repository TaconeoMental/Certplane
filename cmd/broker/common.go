package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/broker/audit"
	"github.com/TaconeoMental/certplane/internal/broker/issuer"
	"github.com/TaconeoMental/certplane/internal/broker/store"
	"github.com/TaconeoMental/certplane/internal/logging"
	"github.com/TaconeoMental/certplane/internal/secrets"
	envsecrets "github.com/TaconeoMental/certplane/internal/secrets/env"
	filesecrets "github.com/TaconeoMental/certplane/internal/secrets/file"
	vaultsecrets "github.com/TaconeoMental/certplane/internal/secrets/vault"
)

type brokerStore interface {
	store.CertificateStore
	audit.Recorder
	WriteAuditEvents(ctx context.Context, w io.Writer, limit int) error
	Close() error
}

func loadBrokerConfig(path string) (*config.BrokerConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("--config is required")
	}

	cfg, err := config.LoadBroker(path)
	if err != nil {
		return nil, err
	}

	logging.SetDefault(logging.New(cfg.Logging))
	return cfg, nil
}

func openBrokerStore(cfg *config.BrokerConfig) (brokerStore, error) {
	switch cfg.Store.Driver {
	case "sqlite":
		return store.NewSQLiteStore(cfg.Store.Path)
	case "file":
		slog.Warn("using file store, sqlite is recommended outside development")
		return store.NewFileStore(cfg.Store.Path), nil
	default:
		return nil, fmt.Errorf("unknown store driver %q", cfg.Store.Driver)
	}
}

func buildAuditRecorder(cfg *config.BrokerConfig, storeRecorder audit.Recorder) audit.Recorder {
	if !cfg.AuditEnabled() {
		return audit.NewDiscardRecorder()
	}
	if cfg.Audit.MirrorToLog {
		return audit.NewMultiRecorder(storeRecorder, audit.NewJSONLRecorder(os.Stdout))
	}
	return storeRecorder
}

func buildSecretsProvider(cfg *config.BrokerConfig) (secrets.Provider, error) {
	switch cfg.Secrets.Provider {
	case "env":
		return envsecrets.New(), nil
	case "file":
		return filesecrets.New(), nil
	case "vault", "openbao":
		return vaultsecrets.New(vaultsecrets.Config{
			Address:   cfg.Secrets.Vault.Address,
			Token:     cfg.Secrets.Vault.Token,
			TokenFile: cfg.Secrets.Vault.TokenFile,
			MountPath: cfg.Secrets.Vault.MountPath,
			KVVersion: cfg.Secrets.Vault.KVVersion,
			Key:       cfg.Secrets.Vault.Key,
			Timeout:   cfg.Secrets.Vault.Timeout,
			Namespace: cfg.Secrets.Vault.Namespace,
		})
	default:
		return nil, fmt.Errorf("unknown secrets provider %q", cfg.Secrets.Provider)
	}
}

func buildIssuer(cfg *config.BrokerConfig, _ secrets.Provider) (issuer.Issuer, error) {
	return nil, fmt.Errorf("unknown issuer provider %q", cfg.Issuer.Provider)
}
