package agent

import (
	"fmt"
	"os"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/pki"
)

func Check(cfg *config.AgentConfig) error {
	if _, err := os.Stat(cfg.Identity.Key); err != nil {
		return fmt.Errorf("identity key check failed: %w", err)
	}
	if _, err := os.Stat(cfg.Identity.Cert); err != nil {
		return fmt.Errorf("identity cert check failed: %w", err)
	}
	for _, certCfg := range cfg.Certificates {
		keyData, err := os.ReadFile(certCfg.Key)
		if err != nil {
			return fmt.Errorf("%s: reading key: %w", certCfg.Name, err)
		}
		key, err := pki.ParsePrivateKeyPEM(keyData)
		if err != nil {
			return fmt.Errorf("%s: parsing key: %w", certCfg.Name, err)
		}
		certData, err := os.ReadFile(certCfg.Cert)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: reading cert: %w", certCfg.Name, err)
		}
		cert, err := pki.ParseCertificatePEM(certData)
		if err != nil {
			return fmt.Errorf("%s: parsing cert: %w", certCfg.Name, err)
		}
		if err := pki.CertificateMatchesPrivateKey(cert, key); err != nil {
			return fmt.Errorf("%s: cert/key mismatch: %w", certCfg.Name, err)
		}
	}
	return nil
}
