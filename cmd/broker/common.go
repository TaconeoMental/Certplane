package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/broker/audit"
	"github.com/TaconeoMental/certplane/internal/broker/store"
	"github.com/TaconeoMental/certplane/internal/logging"
	"github.com/TaconeoMental/certplane/internal/secrets"
	envsecrets "github.com/TaconeoMental/certplane/internal/secrets/providers/env"
	filesecrets "github.com/TaconeoMental/certplane/internal/secrets/providers/file"
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
	default:
		return nil, fmt.Errorf("unknown secrets provider %q", cfg.Secrets.Provider)
	}
}
