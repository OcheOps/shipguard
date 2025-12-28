package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func LoadPolicy(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse policy yaml: %w", err)
	}

	return &cfg, nil
}
