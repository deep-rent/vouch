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

package config_test

import (
	"path/filepath"
	"testing"
	"time"

	"os"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestDefaults(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: https://foo.bar/.well-known/jwks.json
  rules:
    - mode: allow
      when: "true"
      user: '"alice"'
      roles: '["_admin"]'
`
	path := writeConfig(t, yml)

	cfg, _, err := config.Load(path)
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

	remote := keys.Remote
	assert.Equal(t, "https://foo.bar/.well-known/jwks.json", remote.Endpoint)
	assert.Equal(t, 30*time.Minute, remote.Interval)
	assert.Equal(t, "Vouch/dev", remote.UserAgent)

	rules := guard.Rules
	require.Len(t, rules, 1)

	r := rules[0]
	assert.False(t, r.Deny)
	assert.Equal(t, `"alice"`, r.User)
	assert.Equal(t, `["_admin"]`, r.Roles)
}

func TestNoRulesError(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: https://foo.bar/.well-known/jwks.json
  rules: []
`
	_, _, err := config.Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rules: at least one rule")
}

func TestInvalidProxySchemeError(t *testing.T) {
	yml := `
proxy:
  scheme: ftp
guard:
  token:
    keys:
      remote:
        endpoint: https://foo.bar/.well-known/jwks.json
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := config.Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy.scheme: must be 'http' or 'https'")
}

func TestMissingKeysSourceError(t *testing.T) {
	yml := `
guard:
  token:
    keys: {}
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := config.Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(
		t,
		err.Error(),
		`at least one of "static" or "remote.endpoint"`,
	)
}

func TestRuleUserInDenyError(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: https://foo.bar/.well-known/jwks.json
  rules:
    - mode: deny
      when: "true"
      user: '"bob"'
`
	_, _, err := config.Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user: must not be set in")
}

func TestRolesWithoutUserError(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: https://foo.bar/.well-known/jwks.json
  rules:
    - mode: allow
      when: "true"
      roles: '["r1"]'
`
	_, _, err := config.Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "roles: cannot be set without user")
}

func TestRemoteBadSchemeError(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: ftp://auth.example.com/.well-known/jwks.json
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := config.Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remote.endpoint: illegal url scheme")
}

func TestRemoteNegativeIntervalError(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: https://foo.bar/.well-known/jwks.json
        interval: -5
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := config.Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "interval: must be non-negative")
}

func TestNegativeLeewayError(t *testing.T) {
	yml := `
guard:
  token:
    leeway: -10
    keys:
      remote:
        endpoint: https://foo.bar/.well-known/jwks.json
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := config.Load(writeConfig(t, yml))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "leeway: must be non-negative")
}

func TestHeadersCanonicalization(t *testing.T) {
	yml := `
proxy:
  headers:
    user:
      name: x-vouch-user
    roles:
      name: x-vouch-roles
    token:
      name: x-vouch-token
guard:
  token:
    keys:
      remote:
        endpoint: https://foo.bar/.well-known/jwks.json
  rules:
    - mode: allow
      when: "true"
`
	cfg, _, err := config.Load(writeConfig(t, yml))
	require.NoError(t, err)

	h := cfg.Proxy.Headers
	assert.Equal(t, "X-Vouch-User", h.User.Name)
	assert.Equal(t, "X-Vouch-Roles", h.Roles.Name)
	assert.Equal(t, "X-Vouch-Token", h.Token.Name)
}

func TestLoadAcceptsOptions(t *testing.T) {
	yml := `
guard:
  token:
    keys:
      remote:
        endpoint: https://foo.bar/.well-known/jwks.json
  rules:
    - mode: allow
      when: "true"
`
	_, _, err := config.Load(writeConfig(t, yml), config.WithVersion("1.2.3"))
	require.NoError(t, err)
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name    string
		yml     string
		wantErr string
	}{
		{
			name: "no rules",
			yml: `
guard:
  token:
    keys:
      remote: { endpoint: "https://foo.bar/.well-known/jwks.json" }
  rules: []`,
			wantErr: "rules: at least one rule",
		},
		{
			name: "invalid proxy scheme",
			yml: `
proxy:
  scheme: ftp
guard:
  token:
    keys:
      remote: { endpoint: "https://foo.bar/.well-known/jwks.json" }
  rules:
    - { mode: allow, when: "true" }`,
			wantErr: "proxy.scheme: must be 'http' or 'https'",
		},
		{
			name: "missing keys source",
			yml: `
guard:
  token:
    keys: {}
  rules:
    - { mode: allow, when: "true" }`,
			wantErr: `at least one of "static" or "remote.endpoint"`,
		},
		{
			name: "user in deny rule",
			yml: `
guard:
  token:
    keys:
      remote: { endpoint: "https://foo.bar/.well-known/jwks.json" }
  rules:
    - { mode: deny, when: "true", user: '"bob"' }`,
			wantErr: "user: must not be set in",
		},
		{
			name: "roles without user",
			yml: `
guard:
  token:
    keys:
      remote: { endpoint: "https://foo.bar/.well-known/jwks.json" }
  rules:
    - { mode: allow, when: "true", roles: '["r1"]' }`,
			wantErr: "roles: cannot be set without user",
		},
		{
			name: "remote bad scheme",
			yml: `
guard:
  token:
    keys:
      remote: { endpoint: "ftp://example.com/jwks" }
  rules:
    - { mode: allow, when: "true" }`,
			wantErr: "remote.endpoint: illegal url scheme",
		},
		{
			name: "remote negative interval",
			yml: `
guard:
  token:
    keys:
      remote:
        endpoint: "https://foo.bar/.well-known/jwks.json"
        interval: -5
  rules:
    - { mode: allow, when: "true" }`,
			wantErr: "interval: must be non-negative",
		},
		{
			name: "negative leeway",
			yml: `
guard:
  token:
    leeway: -10
    keys:
      remote: { endpoint: "https://foo.bar/.well-known/jwks.json" }
  rules:
    - { mode: allow, when: "true" }`,
			wantErr: "leeway: must be non-negative",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := config.Load(writeConfig(t, tc.yml))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
