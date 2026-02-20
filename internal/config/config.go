package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/env"
	"github.com/deep-rent/nexus/log"
)

// Represents the application's configuration.
type Config struct {
	JWKSURLString       string `env:"VOUCH_JWKS_URL,required"`
	CouchDBURLString    string `env:"VOUCH_COUCHDB_URL,required"`
	Port                string `env:"VOUCH_PORT,default:8080"`
	RolesClaim          string `env:"VOUCH_ROLES_CLAIM,default:roles"`
	LogLevel            string `env:"VOUCH_LOG_LEVEL,default:info"`
	JWKSFetchTimeout    time.Duration `env:"VOUCH_JWKS_FETCH_TIMEOUT,default:10s"`

	JWKSURL    *url.URL
	CouchDBURL *url.URL
	Level      slog.Level
}

// New creates a new Config instance from environment variables.
func New() (*Config, error) {
	var cfg Config
	if err := env.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	jwksURL, err := url.Parse(cfg.JWKSURLString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VOUCH_JWKS_URL: %w", err)
	}
	cfg.JWKSURL = jwksURL

	couchDBURL, err := url.Parse(cfg.CouchDBURLString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse VOUCH_COUCHDB_URL: %w", err)
	}
	cfg.CouchDBURL = couchDBURL

	parsedLogLevel, err := log.ParseLevel(cfg.LogLevel)
	if err != nil {
		return nil, err
	}
	cfg.Level = parsedLogLevel

	return &cfg, nil
}
