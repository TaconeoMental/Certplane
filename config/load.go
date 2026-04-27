package config

import (
	"errors"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type ConfigFlag struct {
	Path string
}

func (f *ConfigFlag) String() string {
	return f.Path
}

func (f *ConfigFlag) Type() string {
	return "string"
}

func (f *ConfigFlag) Set(val string) error {
	if _, err := os.Stat(val); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("Config file does not exist")
	}

	data, err := os.ReadFile(val)
	if err != nil {
		return fmt.Errorf("Could not read config file")
	}

	var out any
	err = yaml.Unmarshal(data, &out)

	if err != nil {
		return fmt.Errorf("Not a valid YAML file")
	}

	f.Path = val
	return nil
}

func LoadBroker(path string) (*BrokerConfig, error) {
	return load[BrokerConfig](path)
}

func LoadAgent(path string) (*AgentConfig, error) {
	return load[AgentConfig](path)
}

func load[T any](path string) (*T, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}
	var cfg T
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file: %w", err)
	}
	return &cfg, nil
}
