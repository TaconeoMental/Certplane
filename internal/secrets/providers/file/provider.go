package file

import (
	"context"
	"fmt"
	"os"
	"strings"
)

type Provider struct{}

func New() *Provider {
	return &Provider{}
}

func (p *Provider) Get(_ context.Context, name string) (string, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return "", fmt.Errorf("reading secret %s: %w", name, err)
	}
	return strings.TrimSpace(string(data)), nil
}
