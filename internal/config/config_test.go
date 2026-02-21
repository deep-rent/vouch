package config_test

import (
	"testing"
	"time"

	"github.com/deep-rent/vouch/internal/config"
)

func TestLoad(t *testing.T) {
	envVars := map[string]string{
		"VOUCH_LOG_LEVEL":                  "warn",
		"VOUCH_LOG_FORMAT":                 "text",
		"VOUCH_HOST":                       "127.0.0.1",
		"VOUCH_PORT":                       "9090",
		"VOUCH_READ_HEADER_TIMEOUT":        "10",
		"VOUCH_READ_TIMEOUT":               "15",
		"VOUCH_WRITE_TIMEOUT":              "20",
		"VOUCH_IDLE_TIMEOUT":               "120",
		"VOUCH_MAX_HEADER_BYTES":           "1048576",
		"VOUCH_USER_NAME_HEADER":           "X-User",
		"VOUCH_ROLES_HEADER":               "X-Roles",
		"VOUCH_TARGET":                     "http://couchdb:5984",
		"VOUCH_FLUSH_INTERVAL":             "500",
		"VOUCH_MIN_BUFFER_SIZE":            "4096",
		"VOUCH_MAX_BUFFER_SIZE":            "8192",
		"VOUCH_MAX_IDLE_CONNS":             "100",
		"VOUCH_IDLE_CONN_TIMEOUT":          "60",
		"VOUCH_TOKEN_ISSUERS":              "https://a.com,https://b.issuer.com",
		"VOUCH_TOKEN_AUDIENCES":            "api,admin",
		"VOUCH_TOKEN_LEEWAY":               "5",
		"VOUCH_TOKEN_MAX_AGE":              "3600",
		"VOUCH_TOKEN_AUTH_SCHEME":          "OAuth",
		"VOUCH_TOKEN_ROLES_CLAIM":          "roles",
		"VOUCH_KEYS_URL":                   "https://c.com/.well-known/jwks.json",
		"VOUCH_KEYS_USER_AGENT":            "Vouch-Test",
		"VOUCH_KEYS_TIMEOUT":               "5",
		"VOUCH_KEYS_MIN_REFRESH_INTERVAL":  "10",
		"VOUCH_KEYS_MAX_REFRESH_INTERVAL":  "60",
		"VOUCH_KEYS_ATTEMPT_LIMIT":         "3",
		"VOUCH_KEYS_BACKOFF_MIN_DELAY":     "2",
		"VOUCH_KEYS_BACKOFF_MAX_DELAY":     "30",
		"VOUCH_KEYS_BACKOFF_GROWTH_FACTOR": "2.5",
		"VOUCH_KEYS_BACKOFF_JITTER_AMOUNT": "0.1",
	}

	for k, v := range envVars {
		t.Setenv(k, v)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load() returned unexpected error: %v", err)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel: got %q, want %q", cfg.LogLevel, "debug")
	}
	if cfg.LogFormat != "text" {
		t.Errorf("LogFormat: got %q, want %q", cfg.LogFormat, "text")
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Host: got %q, want %q", cfg.Host, "127.0.0.1")
	}
	if cfg.Port != "9090" {
		t.Errorf("Port: got %q, want %q", cfg.Port, "9090")
	}
	if cfg.UserNameHeader != "X-User" {
		t.Errorf("UserNameHeader: got %q, want %q", cfg.UserNameHeader, "X-User")
	}
	if cfg.RolesHeader != "X-Roles" {
		t.Errorf("RolesHeader: got %q, want %q", cfg.RolesHeader, "X-Roles")
	}
	if cfg.TokenAuthScheme != "OAuth" {
		t.Errorf("TokenAuthScheme: got %q, want %q", cfg.TokenAuthScheme, "OAuth")
	}
	if cfg.TokenRolesClaim != "roles" {
		t.Errorf("TokenRolesClaim: got %q, want %q", cfg.TokenRolesClaim, "roles")
	}
	if cfg.KeysURL != "https://c.com/.well-known/jwks.json" {
		t.Errorf("KeysURL: got %q, want %q", cfg.KeysURL, "https://c.com/.well-known/jwks.json")
	}
	if cfg.KeysUserAgent != "Vouch-Test" {
		t.Errorf("KeysUserAgent: got %q, want %q", cfg.KeysUserAgent, "Vouch-Test")
	}
	if cfg.MaxHeaderBytes != 1048576 {
		t.Errorf("MaxHeaderBytes: got %d, want %d", cfg.MaxHeaderBytes, 1048576)
	}
	if cfg.MinBufferSize != 4096 {
		t.Errorf("MinBufferSize: got %d, want %d", cfg.MinBufferSize, 4096)
	}
	if cfg.MaxBufferSize != 8192 {
		t.Errorf("MaxBufferSize: got %d, want %d", cfg.MaxBufferSize, 8192)
	}
	if cfg.MaxIdleConns != 100 {
		t.Errorf("MaxIdleConns: got %d, want %d", cfg.MaxIdleConns, 100)
	}
	if cfg.KeysAttemptLimit != 3 {
		t.Errorf("KeysAttemptLimit: got %d, want %d", cfg.KeysAttemptLimit, 3)
	}
	if expected := 10 * time.Second; cfg.ReadHeaderTimeout != expected {
		t.Errorf("ReadHeaderTimeout: got %v, want %v", cfg.ReadHeaderTimeout, expected)
	}
	if expected := 15 * time.Second; cfg.ReadTimeout != expected {
		t.Errorf("ReadTimeout: got %v, want %v", cfg.ReadTimeout, expected)
	}
	if expected := 20 * time.Second; cfg.WriteTimeout != expected {
		t.Errorf("WriteTimeout: got %v, want %v", cfg.WriteTimeout, expected)
	}
	if expected := 120 * time.Second; cfg.IdleTimeout != expected {
		t.Errorf("IdleTimeout: got %v, want %v", cfg.IdleTimeout, expected)
	}
	if expected := 500 * time.Millisecond; cfg.FlushInterval != expected {
		t.Errorf("FlushInterval: got %v, want %v", cfg.FlushInterval, expected)
	}
	if expected := 60 * time.Second; cfg.IdleConnTimeout != expected {
		t.Errorf("IdleConnTimeout: got %v, want %v", cfg.IdleConnTimeout, expected)
	}
	if expected := 5 * time.Second; cfg.TokenLeeway != expected {
		t.Errorf("TokenLeeway: got %v, want %v", cfg.TokenLeeway, expected)
	}
	if expected := 3600 * time.Second; cfg.TokenMaxAge != expected {
		t.Errorf("TokenMaxAge: got %v, want %v", cfg.TokenMaxAge, expected)
	}
	if expected := 5 * time.Second; cfg.KeysTimeout != expected {
		t.Errorf("KeysTimeout: got %v, want %v", cfg.KeysTimeout, expected)
	}
	if expected := 10 * time.Minute; cfg.KeysMinRefreshInterval != expected {
		t.Errorf("KeysMinRefreshInterval: got %v, want %v", cfg.KeysMinRefreshInterval, expected)
	}
	if expected := 60 * time.Minute; cfg.KeysMaxRefreshInterval != expected {
		t.Errorf("KeysMaxRefreshInterval: got %v, want %v", cfg.KeysMaxRefreshInterval, expected)
	}
	if expected := 2 * time.Second; cfg.KeysBackoffMinDelay != expected {
		t.Errorf("KeysBackoffMinDelay: got %v, want %v", cfg.KeysBackoffMinDelay, expected)
	}
	if expected := 30 * time.Second; cfg.KeysBackoffMaxDelay != expected {
		t.Errorf("KeysBackoffMaxDelay: got %v, want %v", cfg.KeysBackoffMaxDelay, expected)
	}
	if cfg.Target == nil || cfg.Target.String() != "http://couchdb:5984" {
		t.Errorf("Target: got %v, want %q", cfg.Target, "http://couchdb:5984")
	}
	if len(cfg.TokenIssuers) != 2 {
		t.Errorf("TokenIssuers length: got %d, want 2", len(cfg.TokenIssuers))
	} else {
		if cfg.TokenIssuers[0] != "https://a.com" {
			t.Errorf("TokenIssuers[0]: got %q", cfg.TokenIssuers[0])
		}
	}
	if len(cfg.TokenAudiences) != 2 {
		t.Errorf("TokenAudiences length: got %d, want 2", len(cfg.TokenAudiences))
	} else {
		if cfg.TokenAudiences[0] != "api" {
			t.Errorf("TokenAudiences[0]: got %q", cfg.TokenAudiences[0])
		}
	}
	if cfg.KeysBackoffGrowthFactor != 2.5 {
		t.Errorf("KeysBackoffGrowthFactor: got %f, want 2.5", cfg.KeysBackoffGrowthFactor)
	}
	if cfg.KeysBackoffJitterAmount != 0.1 {
		t.Errorf("KeysBackoffJitterAmount: got %f, want 0.1", cfg.KeysBackoffJitterAmount)
	}
}
