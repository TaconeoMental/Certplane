package agent

import (
	"fmt"
	"github.com/TaconeoMental/certplane/config"
	"github.com/TaconeoMental/certplane/internal/fileutil"
)

func checkMustNotExist(path, label string) error {
	exists, err := fileutil.FileExists(path)
	if err != nil {
		return fmt.Errorf("error verifying %s existence: %w", label, err)
	}
	if exists {
		return fmt.Errorf("%s file already exists: %s", label, path)
	}
	return nil
}

func checkMustExist(path, label string) error {
	exists, err := fileutil.FileExists(path)
	if err != nil {
		return fmt.Errorf("error verifying %s existence: %w", label, err)
	}
	if !exists {
		return fmt.Errorf("%s does not exist: %s", label, path)
	}
	return nil
}

func Enroll(config *config.AgentConfig) error {
	if err := checkMustNotExist(config.Identity.Cert, "certificate"); err != nil {
		return err
	}
	if err := checkMustNotExist(config.Identity.Key, "key"); err != nil {
		return err
	}
	if err := checkMustExist(config.Identity.BoostrapToken, "bootstrap token"); err != nil {
		return err
	}
	// leer boostrap
	// generar key local
	// generar CSR
	// llamar a stepca con boostrap y CSR
	// guardar crt
	// borrar bootstrap
	return nil
}
