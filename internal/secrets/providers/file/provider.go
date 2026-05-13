package file

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/TaconeoMental/certplane/internal/secrets"
)

type Provider struct {
	TrimSpace bool
}

func New() *Provider {
	return &Provider{TrimSpace: true}
}

func (p *Provider) Get(ctx context.Context, name string) (string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("%w: file %q", secrets.ErrSecretNotFound, name)
		}
		return "", fmt.Errorf("reading secret file %q: %w", name, err)
	}
	val := string(data)
	if p.TrimSpace {
		val = strings.TrimSpace(val)
	}
	if val == "" {
		return "", fmt.Errorf("%w: file %q", secrets.ErrSecretEmpty, name)
	}
	return val, nil
}
