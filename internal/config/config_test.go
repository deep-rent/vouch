// Copyright (c) 2025-present deep.rent GmbH (https://www.deep.rent)
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

package config

import (
	"path/filepath"
	"testing"

	"os"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestLoadSuccessDefaultsApplied(t *testing.T) {
	yml := `
token:
  keys:
    remote:
      endpoint: https://example.com/jwks
rules:
  - mode: allow
    when: "true"
    user: '"alice"'
`
	path := writeConfig(t, yml)

	cfg, err := Load(path)
	require.NoError(t, err)

	// Proxy defaults
	assert.Equal(t, ":8080", cfg.Proxy.Listen)
	assert.Equal(t, "http://localhost:5984", cfg.Proxy.Target.String())

	// Header defaults
	h := cfg.Proxy.Headers
	assert.Equal(t, "X-Auth-CouchDB-UserName", h.User)
	assert.Equal(t, "X-Auth-CouchDB-Roles", h.Roles)
	assert.Equal(t, "X-Auth-CouchDB-Token", h.Token)
	assert.False(t, cfg.SignerEnabled())

	// Signer defaults
	s := cfg.Proxy.Headers.Signer
	assert.Equal(t, "", s.Secret)
	assert.Nil(t, s.Algorithm)

	// Remote defaults
	assert.Equal(t, 30, int(cfg.Token.Keys.Remote.Interval.Minutes()))

	require.Len(t, cfg.Rules, 1)
	assert.False(t, cfg.Rules[0].Deny)
}

func TestLoadErrorNoRules(t *testing.T) {
	yml := `
token:
  keys:
    remote:
      endpoint: https://example.com/jwks
rules: []
`
	_, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rules: at least one rule")
}

func TestLoadErrorInvalidProxyScheme(t *testing.T) {
	yml := `
proxy:
  target: ftp://host:21
token:
  keys:
    remote:
      endpoint: https://example.com/jwks
rules:
  - mode: allow
    when: "true"
`
	_, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy.target: illegal url scheme")
}

func TestLoadErrorMissingKeysSource(t *testing.T) {
	yml := `
token:
  keys: {}
rules:
  - mode: allow
    when: "true"
`
	_, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `at least one of "static" or "remote.endpoint"`)
}

func TestLoadErrorRuleUserInDeny(t *testing.T) {
	yml := `
token:
  keys:
    remote:
      endpoint: https://example.com/jwks
rules:
  - mode: deny
    when: "true"
    user: '"bob"'
`
	_, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user: must not be set in")
}

func TestLoadErrorRolesWithoutUser(t *testing.T) {
	yml := `
token:
  keys:
    remote:
      endpoint: https://example.com/jwks
rules:
  - mode: allow
    when: "true"
    roles: '["r1"]'
`
	_, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles: cannot be set without user")
}

func TestLoadErrorRemoteBadScheme(t *testing.T) {
	yml := `
token:
  keys:
    remote:
      endpoint: ftp://example.com/jwks
rules:
  - mode: allow
    when: "true"
`
	_, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote.endpoint: illegal url scheme")
}

func TestLoadErrorRemoteNegativeInterval(t *testing.T) {
	yml := `
token:
  keys:
    remote:
      endpoint: https://example.com/jwks
      interval: -5
rules:
  - mode: allow
    when: "true"
`
	_, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "interval: must be non-negative")
}

func TestLoadErrorNegativeLeeway(t *testing.T) {
	yml := `
token:
  leeway: -10
  keys:
    remote:
      endpoint: https://example.com/jwks
rules:
  - mode: allow
    when: "true"
`
	_, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "leeway: must be non-negative")
}

func TestHeadersCanonicalization(t *testing.T) {
	yml := `
proxy:
  headers:
    user: x-custom-user
    roles: x-custom-roles
    token: x-custom-token
token:
  keys:
    remote:
      endpoint: https://example.com/jwks
rules:
  - mode: allow
    when: "true"
`
	cfg, err := Load(writeConfig(t, yml))
	require.NoError(t, err)

	h := cfg.Proxy.Headers
	assert.Equal(t, "X-Custom-User", h.User)
	assert.Equal(t, "X-Custom-Roles", h.Roles)
	assert.Equal(t, "X-Custom-Token", h.Token)
}
