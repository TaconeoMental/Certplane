package agent

import (
	"fmt"
	"os"
	"strings"

	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/fileutil"
	"github.com/TaconeoMental/certplane/internal/pki"
)

func Enroll(config *config.AgentConfig) error {
	if fileutil.FileExists(config.Identity.Cert) {
		return fmt.Errorf("identity cert already exists")
	}
	if !fileutil.FileExists(config.Identity.BoostrapToken) {
		return fmt.Errorf("%s does not exist", config.Identity.BoostrapToken)
	}

	tokenData, _ := os.ReadFile(config.Identity.BoostrapToken)
	token := strings.TrimSpace(string(tokenData))
	_ = token

	keyPair, err := pki.NewECDSAKeyPair()
	if err != nil {
		return fmt.Errorf("generating keypair: %w", err)
	}

	csrPEM, err := pki.GenerateCSR(keyPair.PrivateKey, config.Identity.CN)
	if err != nil {
		return fmt.Errorf("generating CSR: %w", err)
	}

	_ = csrPEM
	// llamar a stepca con boostrap y CSR
	// guardar crt
	// borrar bootstrap
	return nil
}
