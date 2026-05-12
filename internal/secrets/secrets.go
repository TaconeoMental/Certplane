package secrets

import "context"

type Provider interface {
	Get(ctx context.Context, name string) (string, error)
}
