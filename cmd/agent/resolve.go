package main

import (
	"fmt"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/ca"
	"github.com/TaconeoMental/certplane/internal/ca/providers/stepca"
)

func resolveIdentityCA(cfg *config.AgentConfig) (ca.IdentityCA, error) {
	switch cfg.Identity.CAProvider {
	case "step-ca":
		return stepca.New(stepca.Config{
			URL:         cfg.Identity.CAURL,
			Fingerprint: cfg.Identity.CAFingerprint,
		})
	default:
		return nil, fmt.Errorf("unknown identity_ca provider: %s", cfg.Identity.CAProvider)
	}
}
