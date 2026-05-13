package pki

import (
	"fmt"
	"time"

	"github.com/TaconeoMental/certplane/internal/fileutil"
)

type Bundle struct {
	CertPEM      []byte `json:"cert_pem"`
	ChainPEM     []byte `json:"chain_pem"`
	FullChainPEM []byte `json:"fullchain_pem"`

	LeafSerialNumber string    `json:"serial_number"`
	NotBefore        time.Time `json:"not_before"`
	NotAfter         time.Time `json:"not_after"`
}

func (b *Bundle) WriteToDisk(certPath, chainPath, fullchainPath string) error {
	files := []struct {
		path string
		data []byte
	}{
		{certPath, b.CertPEM},
		{chainPath, b.ChainPEM},
		{fullchainPath, b.FullChainPEM},
	}
	for _, file := range files {
		if err := fileutil.WriteFileAtomic(file.path, file.data, 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", file.path, err)
		}
	}
	return nil
}
