package config

import (
	"fmt"
	"os"

	"github.com/deep-rent/vouch/internal/rule"
	"gopkg.in/yaml.v3"
)

type Headers struct {
	User string `yaml:"user,omitempty"`
	Role string `yaml:"role,omitempty"`
	Hash string `yaml:"hash,omitempty"`
}

type Config struct {
	Source  string        `yaml:"source,omitempty"`
	Target  string        `yaml:"target,omitempty"`
	Headers Headers       `yaml:"headers,omitempty"`
	Rules   []rule.Config `yaml:"rules"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file '%s': %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return &cfg, nil
}
