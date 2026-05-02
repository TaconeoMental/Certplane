package pki

import (
	"fmt"
	"os"
	"path/filepath"
)

type Bundle struct {
	CertPEM      []byte
	ChainPEM     []byte
	FullChainPEM []byte
}

func (b *Bundle) WriteToDisk(certPath, chainPath, fullchainPath string) error {
	files := map[string][]byte{
		certPath:      b.CertPEM,
		chainPath:     b.ChainPEM,
		fullchainPath: b.FullChainPEM,
	}

	for path, data := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return fmt.Errorf("creating directory for %s: %w", path, err)
		}
		if err := os.WriteFile(path, data, 0644); err != nil {
			return fmt.Errorf("writing %s: %w", path, err)
		}
	}

	return nil
}
