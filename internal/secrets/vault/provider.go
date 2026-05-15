package vault

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	vaultapi "github.com/hashicorp/vault/api"

	"github.com/TaconeoMental/certplane/internal/secrets"
)

type Config struct {
	Address   string
	Token     string
	TokenFile string
	MountPath string
	KVVersion int
	Key       string
	Timeout   time.Duration
	Namespace string
}

type Provider struct {
	cfg    Config
	client *vaultapi.Client
}

func New(cfg Config) (*Provider, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault address is required")
	}
	if cfg.MountPath == "" {
		cfg.MountPath = "secret"
	}
	if cfg.KVVersion == 0 {
		cfg.KVVersion = 2
	}
	if cfg.Key == "" {
		cfg.Key = "value"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	token, err := resolveToken(cfg)
	if err != nil {
		return nil, err
	}

	apiCfg := vaultapi.DefaultConfig()
	apiCfg.Address = strings.TrimRight(cfg.Address, "/")
	apiCfg.HttpClient = &http.Client{Timeout: cfg.Timeout}

	client, err := vaultapi.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}
	client.SetToken(token)
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	return &Provider{cfg: cfg, client: client}, nil
}

func (p *Provider) Get(ctx context.Context, name string) (string, error) {
	name = strings.Trim(strings.TrimSpace(name), "/")
	if name == "" {
		return "", fmt.Errorf("vault secret name is empty")
	}

	data, err := p.read(ctx, name)
	if err != nil {
		return "", err
	}

	raw, ok := data[p.cfg.Key]
	if !ok {
		return "", fmt.Errorf("%w: secret=%q key=%q", secrets.ErrSecretNotFound, name, p.cfg.Key)
	}
	val, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("vault secret %q key %q has type %T, expected string", name, p.cfg.Key, raw)
	}
	val = strings.TrimSpace(val)
	if val == "" {
		return "", fmt.Errorf("%w: vault secret=%q key=%q", secrets.ErrSecretEmpty, name, p.cfg.Key)
	}
	return val, nil
}

func (p *Provider) read(ctx context.Context, name string) (map[string]any, error) {
	switch p.cfg.KVVersion {
	case 1:
		secret, err := p.client.KVv1(p.cfg.MountPath).Get(ctx, name)
		if err != nil {
			return nil, normalizeError(err, name)
		}
		if secret == nil || secret.Data == nil {
			return nil, fmt.Errorf("%w: %s", secrets.ErrSecretNotFound, name)
		}
		return secret.Data, nil
	case 2:
		secret, err := p.client.KVv2(p.cfg.MountPath).Get(ctx, name)
		if err != nil {
			return nil, normalizeError(err, name)
		}
		if secret == nil || secret.Data == nil {
			return nil, fmt.Errorf("%w: %s", secrets.ErrSecretNotFound, name)
		}
		return secret.Data, nil
	default:
		return nil, fmt.Errorf("unsupported vault KV version %d", p.cfg.KVVersion)
	}
}

func normalizeError(err error, name string) error {
	var responseErr *vaultapi.ResponseError
	if errors.As(err, &responseErr) && responseErr.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", secrets.ErrSecretNotFound, name)
	}
	return err
}

func resolveToken(cfg Config) (string, error) {
	var token string
	switch {
	case cfg.Token != "":
		token = cfg.Token
	case cfg.TokenFile != "":
		data, err := os.ReadFile(cfg.TokenFile)
		if err != nil {
			return "", fmt.Errorf("reading vault token file %q: %w", cfg.TokenFile, err)
		}
		token = string(data)
	default:
		token = os.Getenv("VAULT_TOKEN")
		if token == "" {
			token = os.Getenv("BAO_TOKEN")
		}
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("vault token is empty")
	}
	return token, nil
}
