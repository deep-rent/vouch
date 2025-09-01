package config

import (
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
	src := strings.TrimSpace(cfg.Source)
	if src == "" {
		src = ":8080"
	}
	tgt := strings.TrimSpace(cfg.Target)
	if tgt == "" {
		tgt = "http://localhost:3000"
	}
	return &Config{
		Source: src,
		Target: tgt,
	}, nil
}
