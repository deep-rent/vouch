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
	"net/url"
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
	Proxy Proxy `yaml:"proxy"`
	// Token configures how incoming bearer tokens are validated.
	// This section is mandatory.
	Token Token `yaml:"token"`
	// Rules defines ordered authorization rules.
	// The first matching rule decides the outcome. At least one
	// rule is required.
	Rules []Rule `yaml:"rules"`
}

// validate applies defaults and checks the configuration for correctness.
func (c *Config) validate() error {
	if err := c.Proxy.validate(); err != nil {
		return fmt.Errorf("proxy.%w", err)
	}
	if err := c.Token.validate(); err != nil {
		return fmt.Errorf("token.%w", err)
	}
	if len(c.Rules) == 0 {
		return errors.New("rules: at least one rule must be specified")
	}
	for i := range c.Rules {
		if err := c.Rules[i].validate(); err != nil {
			return fmt.Errorf("rules[%d].%w", i, err)
		}
	}
	return nil
}

// Proxy configures the HTTP listener and upstream target.
type Proxy struct {
	// Listen is the TCP address the server listens on, in the form host:port.
	// Defaults to "":8080".
	Listen string `yaml:"listen"`
	// TargetRaw will be mapped to Target after parsing.
	TargetRaw string `yaml:"target"`
	// Target is the CouchDB URL to which requests are proxied.
	// Defaults to "http://localhost:5984".
	Target *url.URL `yaml:"-"`
	// Headers customizes the proxy headers sent to CouchDB.
	// If omitted, the CouchDB-compatible defaults are used.
	Headers Headers `yaml:"headers"`
}

// validate applies defaults and checks the configuration for correctness.
func (p *Proxy) validate() error {
	if strings.TrimSpace(p.Listen) == "" {
		p.Listen = ":8080"
	}
	if strings.TrimSpace(p.TargetRaw) == "" {
		p.TargetRaw = "http://localhost:5984"
	}
	u, err := url.Parse(p.TargetRaw)
	if err != nil {
		return fmt.Errorf("target: invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target: illegal url scheme %q", u.Scheme)
	}
	p.Target = u
	if err := p.Headers.validate(); err != nil {
		return fmt.Errorf("headers.%w", err)
	}
	return nil
}

// Headers customizes the proxy headers forwarded to CouchDB.
type Headers struct {
	// Secret is the CouchDB proxy secret used to sign the token header.
	// If empty, signing is disabled (not recommended in production).
	Secret string `yaml:"secret"`
	// User is the proxy header name that carries the CouchDB user name.
	// Default: "X-Auth-CouchDB-UserName".
	User string `yaml:"user"`
	// Roles is the proxy header name that carries comma-separated roles.
	// Default: "X-Auth-CouchDB-Roles".
	Roles string `yaml:"roles"`
	// Token is the proxy header name that carries the signed token proving
	// the authenticity of the User header.
	// Default: "X-Auth-CouchDB-Token".
	Token string `yaml:"token"`
	// Anonymous allows forwarding requests without an authenticated user.
	// A request is considered anonymous if the deciding rule does not set
	// a user or if the user expression yields an empty string. If false,
	// such requests are denied with 401 Unauthorized.
	Anonymous bool `yaml:"anonymous"`
}

// validate applies defaults and checks the configuration for correctness.
func (h *Headers) validate() error {
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
	return nil
}

// Remote configures periodic retrieval of a JWKS from a remote endpoint.
type Remote struct {
	// Endpoint is the HTTPS URL from which the JWKS is retrieved.
	// Required if no static key set is provided.
	Endpoint string `yaml:"endpoint"`
	// IntervalMin will be mapped to Interval after parsing.
	IntervalMin int64 `yaml:"interval"`
	// Interval is the poll interval measured in minutes.
	// Defaults to 30 (minutes).
	Interval time.Duration `yaml:"-"`
}

// validate applies defaults and checks the configuration for correctness.
func (r *Remote) validate() error {
	r.Endpoint = strings.TrimSpace(r.Endpoint)
	if r.Endpoint != "" {
		u, err := url.Parse(r.Endpoint)
		if err != nil {
			return fmt.Errorf("endpoint: invalid url: %w", err)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return fmt.Errorf("endpoint: illegal url scheme %q", u.Scheme)
		}
	}
	if r.IntervalMin < 0 {
		return errors.New("interval: must be non-negative")
	} else if r.IntervalMin == 0 {
		r.IntervalMin = 30
	}
	r.Interval = time.Duration(r.IntervalMin) * time.Minute
	return nil
}

// Keys configures sources of JWK material used to verify token signatures.
// Static and remote sources are merged when both are provided.
type Keys struct {
	// Static is a filesystem path to a JWKS document.
	// If not provided, a remote endpoint must be configured.
	Static string `yaml:"static"`
	// Remote specifies a JWKS endpoint to fetch and refresh keys from.
	// If not provided, a static JWKS file must be configured.
	Remote Remote `yaml:"remote"`
}

// validate applies defaults and checks the configuration for correctness.
func (k *Keys) validate() error {
	k.Static = strings.TrimSpace(k.Static)
	if err := k.Remote.validate(); err != nil {
		return fmt.Errorf("remote.%w", err)
	}

	if k.Static == "" && k.Remote.Endpoint == "" {
		return fmt.Errorf("at least one of %q or %q must be set",
			"static", "remote.endpoint",
		)
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
	Issuer string `yaml:"issuer"`
	// Audience is the value that the "aud" claim is expected to contain.
	// If omitted, the audience is not validated.
	Audience string `yaml:"audience"`
	// LeewaySec will be mapped to Leeway after parsing.
	LeewaySec int64 `yaml:"leeway"`
	// Leeway is the allowed clock skew interpreted as seconds. Concerns
	// validation of the "exp", "nbf", and "iat" claims.
	// Defaults to 0 (no additional skew).
	Leeway time.Duration `yaml:"-"`
	// Clock allows injecting a custom clock for testing purposes.
	// Not configurable via YAML.
	Clock jwt.Clock `yaml:"-"`
}

// validate applies defaults and checks the configuration for correctness.
func (t *Token) validate() error {
	if err := t.Keys.validate(); err != nil {
		return fmt.Errorf("keys.%w", err)
	}
	if t.Leeway < 0 {
		return errors.New("leeway: must be non-negative")
	}
	t.Issuer = strings.TrimSpace(t.Issuer)
	t.Audience = strings.TrimSpace(t.Audience)
	t.Leeway = time.Duration(t.LeewaySec) * time.Second
	return nil
}

// Mode enumerates the decision a Rule applies when its condition is met.
// A rule either allows (optionally authenticating as a user) or denies
// the incoming request.
const (
	// ModeAllow grants access and may authenticate the request on behalf of
	// the specified user with optional roles.
	ModeAllow = "allow"
	// ModeDeny denies access and prevents the request from proceeding.
	ModeDeny = "deny"
)

// Rule represents a single, uncompiled authorization rule loaded from config.
// Expressions in When, User, and Roles are plain strings that must be compiled
// before use.
type Rule struct {
	// Mode selects the decision when the rule matches.
	// Supported values: "allow" or "deny".
	Mode string `yaml:"mode"`
	// Deny is true if mode is ModeDeny, false if mode is ModeAllow.
	Deny bool `yaml:"-"`
	// When specifies the condition under which the rule applies.
	// This expression is mandatory for every rule and must always evaluate to
	// a boolean.
	When string `yaml:"when"`
	// User is an optional expression that determines the CouchDB user name to
	// authenticate as. This field is only used in "allow" mode. If specified,
	// the expression must return a string. It must be left undefined in "deny"
	// mode. An empty or missing result will cause the request to be forwarded
	// anonymously, provided that the configuration allows it (see
	// Headers.Anonymous).
	User string `yaml:"user"`
	// Roles is an optional expression that specifies CouchDB roles for
	// authentication. This field is only used in "allow" mode. The expression
	// must return a slice of strings. It must be left undefined in "deny" mode.
	// Example: '["reader", "writer"]'
	Roles string `yaml:"roles"`
}

// validate applies defaults and checks the configuration for correctness.
func (r *Rule) validate() error {
	switch strings.ToLower(strings.TrimSpace(r.Mode)) {
	case ModeAllow:
		r.Deny = false
	case ModeDeny:
		r.Deny = true
	case "":
		return fmt.Errorf("mode: must be specified")
	default:
		return fmt.Errorf("mode: must be %q or %q", ModeAllow, ModeDeny)
	}
	r.Mode = ""
	r.When = strings.TrimSpace(r.When)
	if r.When == "" {
		return errors.New("when: expression must be specified")
	}

	r.User = strings.TrimSpace(r.User)
	if r.User != "" && r.Deny {
		return fmt.Errorf("user: must not be set in %q mode", ModeDeny)
	}

	r.Roles = strings.TrimSpace(r.Roles)
	if r.Roles != "" {
		if r.Deny {
			return fmt.Errorf("roles: must not be set in %q mode", ModeDeny)
		}
		if r.User == "" {
			return errors.New("roles: cannot be set without user")
		}
	}
	return nil
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

	// Apply defaults, normalize values, and validate.
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}
