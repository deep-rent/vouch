package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/deep-rent/vouch/internal/rule"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Source string        `yaml:"source"`
	Target string        `yaml:"target"`
	Rules  []rule.Config `yaml:"rules"`
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
	source := strings.TrimSpace(cfg.Source)
	if source == "" {
		source = ":8080"
	}
	target := strings.TrimSpace(cfg.Target)
	if target == "" {
		target = "http://localhost:3000"
	}
	rules := cfg.Rules
	if len(rules) == 0 {
		return nil, errors.New("at least one rule is required")
	}
	return &Config{
		Source: source,
		Target: target,
		Rules:  rules,
	}, nil
}
