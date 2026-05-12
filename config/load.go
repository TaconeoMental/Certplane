package config

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadAgent(path string) (*AgentConfig, error) {
	cfg, err := loadYAML[AgentConfig](path)
	if err != nil {
		return nil, err
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating agent config: %w", err)
	}
	return cfg, nil
}

func LoadBroker(path string) (*BrokerConfig, error) {
	cfg, err := loadYAML[BrokerConfig](path)
	if err != nil {
		return nil, err
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating broker config: %w", err)
	}
	return cfg, nil
}

func loadYAML[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading YAML config %q: %w", path, err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var cfg T
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing YAML config %q: %w", path, err)
	}
	return &cfg, nil
}

