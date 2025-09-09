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
	"time"

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
guard:
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

	cfg, _, err := Load(path)
	require.NoError(t, err)

	local := cfg.Local
	assert.Equal(t, ":8080", local.Addr)

	proxy := cfg.Proxy
	assert.Equal(t, "http://localhost:8080", proxy.Target.String())

	headers := proxy.Headers
	assert.Equal(t, "X-Auth-CouchDB-UserName", headers.User.Name)
	assert.False(t, headers.User.Anonymous)
	assert.Equal(t, "X-Auth-CouchDB-Roles", headers.Roles.Name)
	assert.Empty(t, headers.Roles.Default)
	assert.Equal(t, "X-Auth-CouchDB-Token", headers.Token.Name)
	assert.Empty(t, headers.Token.Signer.Secret)
	assert.Nil(t, headers.Token.Signer.Algorithm)

	guard := cfg.Guard

	token := guard.Token
	assert.Empty(t, token.Issuer)
	assert.Empty(t, token.Audience)
	assert.Equal(t, time.Duration(0), token.Leeway)
	assert.Nil(t, token.Clock)

	keys := token.Keys
	assert.Empty(t, keys.Static)
	assert.Equal(t, "https://example.com/jwks", keys.Remote.Endpoint)
	assert.Equal(t, 30*time.Minute, keys.Remote.Interval)

	require.Len(t, guard.Rules, 1)
	assert.False(t, guard.Rules[0].Deny)
}

func TestLoadErrorNoRules(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: https://example.com/jwks
  rules: []
`
	_, _, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rules: at least one rule")
}

func TestLoadErrorInvalidProxyScheme(t *testing.T) {
	yml := `
proxy:
  scheme: ftp
guard:
  token:
    keys:
      remote:
        endpoint: https://example.com/jwks
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy.scheme: must be 'http' or 'https'")
}

func TestLoadErrorMissingKeysSource(t *testing.T) {
	yml := `
guard:
  token:
    keys: {}
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `at least one of "static" or "remote.endpoint"`)
}

func TestLoadErrorRuleUserInDeny(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: https://example.com/jwks
  rules:
    - mode: deny
      when: "true"
      user: '"bob"'
`
	_, _, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user: must not be set in")
}

func TestLoadErrorRolesWithoutUser(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: https://example.com/jwks
  rules:
    - mode: allow
      when: "true"
      roles: '["r1"]'
`
	_, _, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles: cannot be set without user")
}

func TestLoadErrorRemoteBadScheme(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: ftp://example.com/jwks
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote.endpoint: illegal url scheme")
}

func TestLoadErrorRemoteNegativeInterval(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: https://example.com/jwks
        interval: -5
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "interval: must be non-negative")
}

func TestLoadErrorNegativeLeeway(t *testing.T) {
	yml := `
guard:
  token:
    leeway: -10
    keys:
      remote:
        endpoint: https://example.com/jwks
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "leeway: must be non-negative")
}

func TestHeadersCanonicalization(t *testing.T) {
	yml := `
proxy:
  headers:
    user:
      name: x-custom-user
    roles:
      name: x-custom-roles
    token:
      name: x-custom-token
guard:
  token:
    keys:
      remote:
        endpoint: https://example.com/jwks
  rules:
    - mode: allow
      when: "true"
`
	cfg, _, err := Load(writeConfig(t, yml))
	require.NoError(t, err)

	h := cfg.Proxy.Headers
	assert.Equal(t, "X-Custom-User", h.User.Name)
	assert.Equal(t, "X-Custom-Roles", h.Roles.Name)
	assert.Equal(t, "X-Custom-Token", h.Token.Name)
}

func TestLoadAcceptsOptions(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: https://example.com/jwks
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := Load(writeConfig(t, yml), WithVersion("1.2.3"))
	require.NoError(t, err)
}
