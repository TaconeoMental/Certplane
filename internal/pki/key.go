package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/TaconeoMental/certplane/internal/fileutil"
)

func GenerateECDSAKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating ECDSA P-256 key: %w", err)
	}
	return key, nil
}

func MarshalPrivateKeyPEM(key crypto.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key as PKCS#8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}

	var key any
	var err error
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unexpected private key PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key type %T does not implement crypto.Signer", key)
	}
	return signer, nil
}

func EnsureECDSAPrivateKey(path string) (crypto.Signer, []byte, error) {
	exists, err := fileutil.FileExists(path)
	if err != nil {
		return nil, nil, err
	}
	if exists {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, fmt.Errorf("reading private key %q: %w", path, err)
		}
		key, err := ParsePrivateKeyPEM(data)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing private key %q: %w", path, err)
		}
		return key, data, nil
	}

	key, err := GenerateECDSAKey()
	if err != nil {
		return nil, nil, err
	}
	pemData, err := MarshalPrivateKeyPEM(key)
	if err != nil {
		return nil, nil, err
	}
	if err := fileutil.WriteFileAtomic(path, pemData, 0o600); err != nil {
		return nil, nil, fmt.Errorf("writing private key %q: %w", path, err)
	}
	return key, pemData, nil
}
