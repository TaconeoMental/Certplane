package policy

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// TODO: re-use generic config load function?
func Load(path string) (*CompiledPolicy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy %q: %w", path, err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing YAML policy %q: %w", path, err)
	}

	return Compile(cfg)
}
