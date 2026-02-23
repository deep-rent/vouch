// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config_test

import (
	"testing"
	"time"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	vars := map[string]string{
		"VOUCH_LOG_LEVEL":                  "warn",
		"VOUCH_LOG_FORMAT":                 "text",
		"VOUCH_HOST":                       "127.0.0.1",
		"VOUCH_PORT":                       "9090",
		"VOUCH_READ_HEADER_TIMEOUT":        "10",
		"VOUCH_READ_TIMEOUT":               "15",
		"VOUCH_WRITE_TIMEOUT":              "20",
		"VOUCH_IDLE_TIMEOUT":               "120",
		"VOUCH_MAX_HEADER_BYTES":           "1048576",
		"VOUCH_USER_NAME_HEADER":           "X-Vouch-User",
		"VOUCH_ROLES_HEADER":               "X-Vouch-Roles",
		"VOUCH_TARGET":                     "http://couchdb:5984",
		"VOUCH_FLUSH_INTERVAL":             "500",
		"VOUCH_MIN_BUFFER_SIZE":            "4096",
		"VOUCH_MAX_BUFFER_SIZE":            "8192",
		"VOUCH_MAX_IDLE_CONNS":             "100",
		"VOUCH_IDLE_CONN_TIMEOUT":          "60",
		"VOUCH_TOKEN_ISSUERS":              "https://auth-1.com,https://auth-2.com",
		"VOUCH_TOKEN_AUDIENCES":            "basic,admin",
		"VOUCH_TOKEN_LEEWAY":               "5",
		"VOUCH_TOKEN_MAX_AGE":              "3600",
		"VOUCH_TOKEN_AUTH_SCHEME":          "OAuth",
		"VOUCH_TOKEN_ROLES_CLAIM":          "roles",
		"VOUCH_KEYS_URL":                   "https://auth.com/.well-known/jwks.json",
		"VOUCH_KEYS_TIMEOUT":               "5",
		"VOUCH_KEYS_MIN_REFRESH_INTERVAL":  "10",
		"VOUCH_KEYS_MAX_REFRESH_INTERVAL":  "60",
		"VOUCH_KEYS_ATTEMPT_LIMIT":         "3",
		"VOUCH_KEYS_BACKOFF_MIN_DELAY":     "2",
		"VOUCH_KEYS_BACKOFF_MAX_DELAY":     "30",
		"VOUCH_KEYS_BACKOFF_GROWTH_FACTOR": "2.5",
		"VOUCH_KEYS_BACKOFF_JITTER_AMOUNT": "0.1",
	}

	for k, v := range vars {
		t.Setenv(k, v)
	}

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "warn", cfg.LogLevel)
	assert.Equal(t, "text", cfg.LogFormat)
	assert.Equal(t, "127.0.0.1", cfg.Host)
	assert.Equal(t, "9090", cfg.Port)
	assert.Equal(t, "X-Vouch-User", cfg.UserNameHeader)
	assert.Equal(t, "X-Vouch-Roles", cfg.RolesHeader)
	assert.Equal(t, "OAuth", cfg.TokenAuthScheme)
	assert.Equal(t, "roles", cfg.TokenRolesClaim)
	assert.Equal(t, "https://auth.com/.well-known/jwks.json", cfg.KeysURL)
	assert.Equal(t, 1048576, cfg.MaxHeaderBytes)
	assert.Equal(t, 4096, cfg.MinBufferSize)
	assert.Equal(t, 8192, cfg.MaxBufferSize)
	assert.Equal(t, 100, cfg.MaxIdleConns)
	assert.Equal(t, 3, cfg.KeysAttemptLimit)
	assert.Equal(t, 10*time.Second, cfg.ReadHeaderTimeout)
	assert.Equal(t, 15*time.Second, cfg.ReadTimeout)
	assert.Equal(t, 20*time.Second, cfg.WriteTimeout)
	assert.Equal(t, 120*time.Second, cfg.IdleTimeout)
	assert.Equal(t, 500*time.Millisecond, cfg.FlushInterval)
	assert.Equal(t, 60*time.Second, cfg.IdleConnTimeout)
	assert.Equal(t, 5*time.Second, cfg.TokenLeeway)
	assert.Equal(t, 3600*time.Second, cfg.TokenMaxAge)
	assert.Equal(t, 5*time.Second, cfg.KeysTimeout)
	assert.Equal(t, 10*time.Minute, cfg.KeysMinRefreshInterval)
	assert.Equal(t, 60*time.Minute, cfg.KeysMaxRefreshInterval)
	assert.Equal(t, 2*time.Second, cfg.KeysBackoffMinDelay)
	assert.Equal(t, 30*time.Second, cfg.KeysBackoffMaxDelay)
	require.NotNil(t, cfg.Target)
	assert.Equal(t, "http://couchdb:5984", cfg.Target.String())
	assert.Len(t, cfg.TokenIssuers, 2)
	assert.Equal(t, "https://auth-1.com", cfg.TokenIssuers[0])
	assert.Equal(t, "https://auth-2.com", cfg.TokenIssuers[1])
	assert.Len(t, cfg.TokenAudiences, 2)
	assert.Equal(t, "basic", cfg.TokenAudiences[0])
	assert.Equal(t, "admin", cfg.TokenAudiences[1])
	assert.Equal(t, 2.5, cfg.KeysBackoffGrowthFactor)
	assert.Equal(t, 0.1, cfg.KeysBackoffJitterAmount)
}

func TestLoadDefaults(t *testing.T) {
	t.Setenv("VOUCH_KEYS_URL", "https://required.com/jwks.json")

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, "info", cfg.LogLevel)
	assert.Equal(t, "json", cfg.LogFormat)
	assert.Equal(t, "0.0.0.0", cfg.Host)
	assert.Equal(t, "8080", cfg.Port)
	assert.Equal(t, 5*time.Second, cfg.ReadHeaderTimeout)
	assert.Equal(t, 30*time.Second, cfg.ReadTimeout)
	assert.Equal(t, time.Duration(0), cfg.WriteTimeout)
	assert.Equal(t, 120*time.Second, cfg.IdleTimeout)
	assert.Equal(t, 0, cfg.MaxHeaderBytes)
	assert.Equal(t, "X-Auth-CouchDB-UserName", cfg.UserNameHeader)
	assert.Equal(t, "X-Auth-CouchDB-Roles", cfg.RolesHeader)
	require.NotNil(t, cfg.Target)
	assert.Equal(t, "http://localhost:5984", cfg.Target.String())
	assert.Equal(t, -1*time.Millisecond, cfg.FlushInterval)
	assert.Equal(t, 32768, cfg.MinBufferSize)
	assert.Equal(t, 262144, cfg.MaxBufferSize)
	assert.Equal(t, 512, cfg.MaxIdleConns)
	assert.Equal(t, 90*time.Second, cfg.IdleConnTimeout)
	assert.Empty(t, cfg.TokenIssuers)
	assert.Empty(t, cfg.TokenAudiences)
	assert.Equal(t, 30*time.Second, cfg.TokenLeeway)
	assert.Equal(t, time.Duration(0), cfg.TokenMaxAge)
	assert.Equal(t, "Bearer", cfg.TokenAuthScheme)
	assert.Equal(t, "_couchdb.roles", cfg.TokenRolesClaim)
	assert.Equal(t, "https://required.com/jwks.json", cfg.KeysURL)
	assert.Equal(t, 10*time.Second, cfg.KeysTimeout)
	assert.Equal(t, 60*time.Minute, cfg.KeysMinRefreshInterval)
	assert.Equal(t, 28800*time.Minute, cfg.KeysMaxRefreshInterval)
	assert.Equal(t, 0, cfg.KeysAttemptLimit)
	assert.Equal(t, 1*time.Second, cfg.KeysBackoffMinDelay)
	assert.Equal(t, 120*time.Second, cfg.KeysBackoffMaxDelay)
	assert.Equal(t, 1.75, cfg.KeysBackoffGrowthFactor)
	assert.Equal(t, 0.66, cfg.KeysBackoffJitterAmount)
}
