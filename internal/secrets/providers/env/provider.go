package env

import (
	"context"
	"fmt"
	"os"

	"github.com/TaconeoMental/certplane/internal/secrets"
)

type Provider struct{}

func New() *Provider {
	return &Provider{}
}

func (p *Provider) Get(ctx context.Context, name string) (string, error) {
	val, ok := os.LookupEnv(name)
	if !ok {
		return "", fmt.Errorf("%w: environment variable %q", secrets.ErrSecretNotFound, name)
	}
	if val == "" {
		return "", fmt.Errorf("%w: environment variable %q", secrets.ErrSecretEmpty, name)
	}
	return val, nil
}
