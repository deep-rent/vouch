package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/goccy/go-json"
	"github.com/goccy/go-yaml"
)

type Config struct {
	// Config data...
}

// Decoder decodes raw configuration data into the provided Go value.
type Decoder func(data []byte, v any) error

// infer detects the Decoder to use based on the file extension.
// Returns nil if no suitable Decoder is found.
func infer(path string) Decoder {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return json.Unmarshal
	case ".yaml", ".yml":
		return yaml.Unmarshal
	default:
		return nil
	}
}

// Default returns a Config struct initialized with defaults.
func Default() Config {
	return Config{}
}

// Load reads the configuration file from the given path, decodes it,
// and returns a populated Config struct by value.
// If dec is nil, it attempts to infer the decoder from the file extension.
func Load(path string, dec Decoder) (Config, error) {
	if dec == nil {
		if dec = infer(path); dec == nil {
			return Config{}, errors.New("unsupported format")
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading failed: %w", err)
	}
	cfg := Default()
	if err := dec(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing failed: %w", err)
	}
	return cfg, nil
}
