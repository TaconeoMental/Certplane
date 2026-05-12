package config

import (
	"errors"
	"fmt"
)

type LoggingConfig struct {
	Level       string `yaml:"level"`       // debug | info | warn | error
	Format      string `yaml:"format"`      // text | json
	Destination string `yaml:"destination"` // stdout | stderr
}

func (c *LoggingConfig) ApplyDefaults(level, format, destination string) {
	if c.Level == "" {
		c.Level = level
	}
	if c.Format == "" {
		c.Format = format
	}
	if c.Destination == "" {
		c.Destination = destination
	}
}

func (c LoggingConfig) Validate() error {
	var errs []error
	switch c.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("logging.level must be debug, info, warn or error"))
	}
	switch c.Format {
	case "text", "json":
	default:
		errs = append(errs, fmt.Errorf("logging.format must be text or json"))
	}
	switch c.Destination {
	case "stdout", "stderr":
	default:
		errs = append(errs, fmt.Errorf("logging.destination must be stdout or stderr"))
	}
	return errors.Join(errs...)
}
