package secrets

import (
	"context"
	"errors"
)

var (
	ErrSecretNotFound = errors.New("secret not found")
	ErrSecretEmpty    = errors.New("secret is empty")
)

type Provider interface {
	Get(ctx context.Context, name string) (string, error)
}
