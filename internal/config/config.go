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
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"gopkg.in/yaml.v3"
)

// Config represents the entire application configuration.
type Config struct {
	// Proxy configures the local HTTP server and reverse proxy behavior.
	// If omitted, defaults are applied.
	Proxy Proxy `yaml:"proxy,omitempty"`
	// Token configures how incoming bearer tokens are validated.
	// This section is mandatory.
	Token Token `yaml:"token"`
	// Rules defines ordered authorization rules.
	// The first matching rule decides the outcome. At least one
	// rule is required.
	Rules []Rule `yaml:"rules"`
}

// setDefaults applies default values to the configuration.
func (c *Config) setDefaults() {
	c.Proxy.setDefaults()
	c.Token.setDefaults()
}

// validate checks the overall configuration for correctness.
func (c *Config) validate() error {
	if len(c.Rules) == 0 {
		return errors.New("rules: at least one rule must be specified")
	}
	if err := c.Token.validate(); err != nil {
		return err
	}
	return nil
}

// Proxy configures the HTTP listener and upstream target.
type Proxy struct {
	// Listen is the TCP address the server listens on, in the form host:port.
	// Defaults to "":8080".
	Listen string `yaml:"listen,omitempty"`
	// Target is the CouchDB URL to which requests are proxied.
	// Defaults to "http://localhost:5984".
	Target string `yaml:"target,omitempty"`
	// Headers customizes the proxy headers sent to CouchDB.
	// If omitted, the CouchDB-compatible defaults are used.
	Headers Headers `yaml:"headers,omitempty"`
}

func (p *Proxy) setDefaults() {
	if strings.TrimSpace(p.Listen) == "" {
		p.Listen = ":8080"
	}
	if strings.TrimSpace(p.Target) == "" {
		p.Target = "http://localhost:5984"
	}
	p.Headers.setDefaults()
}

// Headers customizes the proxy headers forwarded to CouchDB.
type Headers struct {
	// Secret is the CouchDB proxy secret used to sign the token header.
	// If empty, signing is disabled (not recommended in production).
	Secret string `yaml:"secret,omitempty"`
	// User is the proxy header name that carries the CouchDB user name.
	// Default: "X-Auth-CouchDB-UserName".
	User string `yaml:"user,omitempty"`
	// Roles is the proxy header name that carries comma-separated roles.
	// Default: "X-Auth-CouchDB-Roles".
	Roles string `yaml:"roles,omitempty"`
	// Token is the proxy header name that carries the signed token proving
	// the authenticity of the User header.
	// Default: "X-Auth-CouchDB-Token".
	Token string `yaml:"token,omitempty"`
	// Anonymous allows forwarding requests without an authenticated user.
	// If false, anonymous requests are rejected with 401 Unauthorized.
	Anonymous bool `yaml:"anonymous,omitempty"`
}

func (h *Headers) setDefaults() {
	h.Secret = strings.TrimSpace(h.Secret)
	if user := strings.TrimSpace(h.User); user == "" {
		h.User = "X-Auth-CouchDB-UserName"
	} else {
		h.User = http.CanonicalHeaderKey(user)
	}
	if roles := strings.TrimSpace(h.Roles); roles == "" {
		h.Roles = "X-Auth-CouchDB-Roles"
	} else {
		h.Roles = http.CanonicalHeaderKey(roles)
	}
	if token := strings.TrimSpace(h.Token); token == "" {
		h.Token = "X-Auth-CouchDB-Token"
	} else {
		h.Token = http.CanonicalHeaderKey(token)
	}
}

// Remote configures periodic retrieval of a JWKS from a remote endpoint.
type Remote struct {
	// Endpoint is the HTTPS URL from which the JWKS is retrieved.
	// Required if no static key set is provided.
	Endpoint string `yaml:"endpoint,omitempty"`
	// Interval is the poll interval measured in minutes.
	// Default to 30 (minutes).
	Interval time.Duration `yaml:"interval,omitempty"`
}

func (r *Remote) setDefaults() {
	r.Endpoint = strings.TrimSpace(r.Endpoint)
	// YAML unmarshals a number to nanoseconds. We interpret it as minutes.
	if r.Interval == 0 {
		r.Interval = 30 * time.Minute
	} else {
		r.Interval *= time.Minute
	}
}

// Keys configures sources of JWK material used to verify token signatures.
// Static and remote sources are merged when both are provided.
type Keys struct {
	// Static is a filesystem path to a JWKS document.
	// If not provided, a remote endpoint must be configured.
	Static string `yaml:"static,omitempty"`
	// Remote specifies a JWKS endpoint to fetch and refresh keys from.
	// If not provided, a static JWKS file must be configured.
	Remote Remote `yaml:"remote,omitempty"`
}

func (k *Keys) setDefaults() {
	k.Static = strings.TrimSpace(k.Static)
	k.Remote.setDefaults()
}

func (k *Keys) validate() error {
	if k.Static == "" && k.Remote.Endpoint == "" {
		return errors.New("token.keys: at least one of 'static' or 'remote.endpoint' must be set")
	}
	return nil
}

// Token configures the validation of access tokens.
type Token struct {
	// Keys specifies the JWK source(s) used for signature verification.
	// This setting is required.
	Keys Keys `yaml:"keys"`
	// Issuer is the expected value of the "iss" claim.
	// If omitted, the issuer is not validated.
	Issuer string `yaml:"issuer,omitempty"`
	// Audience is the value that the "aud" claim is expected to contain.
	// If omitted, the audience is not validated.
	Audience string `yaml:"audience,omitempty"`
	// Leeway is the amount of time to allow for clock skew in seconds.
	// Defaults to 0 (no additional skew).
	Leeway time.Duration `yaml:"leeway,omitempty"`
	// Clock allows injecting a custom clock for testing purposes.
	// Not configurable via YAML.
	Clock jwt.Clock `yaml:"-"`
}

func (t *Token) setDefaults() {
	t.Keys.setDefaults()
	t.Issuer = strings.TrimSpace(t.Issuer)
	t.Audience = strings.TrimSpace(t.Audience)
	// YAML unmarshals a number to nanoseconds. We interpret it as seconds.
	t.Leeway *= time.Second
}

func (t *Token) validate() error {
	if t.Leeway < 0 {
		return errors.New("token.leeway: must be non-negative")
	}
	return t.Keys.validate()
}

// Rule represents a single, uncompiled authorization rule loaded from config.
// Expressions in When, User, and Roles are plain strings that must be compiled
// before use.
type Rule struct {
	// Mode selects the decision when the rule matches.
	// Supported values: "allow" or "deny".
	Mode string `yaml:"mode"`
	// When specifies the condition under which the rule applies.
	// This expression is mandatory for every rule and must always evaluate to
	// a boolean.
	When string `yaml:"when"`
	// User is an optional expression that determines the CouchDB user nameto
	// authenticate as. This field is only used in "allow" mode. If specified,
	// the expression must return a string. It must be left undefined in "deny"
	// mode. An empty or missing result will cause the request to be forwarded
	// anonymously, provided that the configuration allows it.
	// Example: 'Claim("sub")'
	User string `yaml:"user,omitempty"`
	// Roles is an optional expression that specifies CouchDB roles for
	// authentication. This field is only used in "allow" mode. The expression
	// must return a slice of strings. It must be left undefined in "deny" mode.
	// Example: '["reader", "writer"]'
	Roles string `yaml:"roles,omitempty"`
}

// Load reads a YAML configuration file from path, applies defaults, normalizes
// values, and performs basic validation. It returns a fully-populated Config.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read file %q: %w", path, err)
	}

	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse yaml: %w", err)
	}

	// Apply defaults and validation logic.
	cfg.setDefaults()
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
