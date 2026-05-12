package main

import (
	"fmt"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/ca"
	"github.com/TaconeoMental/certplane/internal/logging"
	"github.com/TaconeoMental/certplane/internal/ca/providers/stepca"
)

func loadAgentConfig(path string) (*config.AgentConfig, error) {
	if path == "" {
		return nil, fmt.Errorf("--config is required")
	}
	cfg, err := config.LoadAgent(path)
	if err != nil {
		return nil, err
	}
	logging.SetDefault(logging.New(cfg.Logging))
	return cfg, nil
}

func loadAgentRuntime(path string) (*config.AgentConfig, ca.IdentityCA, error) {
	cfg, err := loadAgentConfig(path)
	if err != nil {
		return nil, nil, err
	}
	identityCA, err := resolveIdentityCA(cfg)
	if err != nil {
		return nil, nil, err
	}
	return cfg, identityCA, nil
}

func resolveIdentityCA(cfg *config.AgentConfig) (ca.IdentityCA, error) {
	switch cfg.Identity.Provider {
	case "step-ca":
		return stepca.New(stepca.Config{
			URL:         cfg.Identity.StepCA.URL,
			Fingerprint: cfg.Identity.StepCA.Fingerprint,
			RootCAPath:  cfg.Identity.StepCA.RootCABundle,
			Timeout:     cfg.Identity.StepCA.Timeout,
		})
	default:
		return nil, fmt.Errorf("unknown identity CA provider %q", cfg.Identity.Provider)
	}
}
