package env

import (
	"context"
	"fmt"
	"os"
)

type Provider struct{}

func New() *Provider {
	return &Provider{}
}

func (p *Provider) Get(_ context.Context, name string) (string, error) {
	val := os.Getenv(name)
	if val == "" {
		return "", fmt.Errorf("environment variable %s is not set", name)
	}
	return val, nil
}
