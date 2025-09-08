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
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwt"
	"gopkg.in/yaml.v3"
)

// Runtime vs wire types
//
// The exported (capitalized) types (Config, Proxy, Headers, etc.) are the
// normalized runtime representations consumed by the rest of the application.
//
// YAML is unmarshaled into a parallel set of unexported "wire" structs
// (config, proxy, headers, etc.) that map 1:1 to the YAML schema and keep raw
// string or primitive values. Each wire struct has a validate() method that:
//   1. Supplies defaults
//   2. Normalizes values (e.g., trim whitespace, canonicalize header names)
//   3. Performs structural & semantic validation
//   4. Produces the corresponding exported runtime value
//
// No exported type is unmarshaled directly. The flow is:
//   Load -> decode YAML into wire 'config' -> config.validate() -> runtime Config.

// Config represents the entire application configuration.
type Config struct {
	// Proxy configures the local HTTP server and reverse proxy behavior.
	Proxy Proxy
	// Token configures how incoming bearer tokens are validated.
	Token Token
	// Rules defines ordered authorization rules. The first matching rule
	// decides the outcome. At least one rule is required.
	Rules []Rule
}

// SignerEnabled indicates whether or not CouchDB proxy signing is enabled.
func (c Config) SignerEnabled() bool {
	return c.Proxy.Headers.Signer.Secret != ""
}

// Proxy configures the HTTP listener and upstream target.
type Proxy struct {
	// Listen is the TCP address the server listens on, in the form 'host:port'
	// or ':port' to listen on all interfaces.
	Listen string
	// Target is the CouchDB URL to which requests are proxied.
	Target *url.URL
	// Headers customizes the proxy headers sent to CouchDB.
	Headers Headers
}

// Headers customizes the proxy headers forwarded to CouchDB.
type Headers struct {
	// Signer configures the signing of CouchDB proxy authentication tokens.
	Signer Signer
	// User is the proxy header name that carries the CouchDB user name.
	User string
	// Roles is the proxy header name that carries comma-separated roles.
	Roles string
	// Token is the proxy header name that carries the signed token proving
	// the authenticity of the User header.
	Token string
	// Anonymous allows forwarding requests without an authenticated user.
	// A request is considered anonymous if the deciding rule does not set
	// a user or if the user expression yields an empty string. If false,
	// such requests are denied with 401 Unauthorized.
	Anonymous bool
}

// Signer configures the signing of CouchDB proxy authentication tokens.
type Signer struct {
	// Secret is the CouchDB secret key used to sign the proxy token header.
	// If empty, the token header will be omitted from forwarded requests.
	Secret string
	// Algorithm returns the hash function used for signing. If it is nil, the
	// default SHA-256 is used.
	Algorithm func() hash.Hash
}

// Remote configures periodic retrieval of a JWKS from a remote endpoint.
type Remote struct {
	// Endpoint is the HTTPS URL from which the JWKS is retrieved.
	// Required if no static key set is provided.
	Endpoint string
	// Interval is the poll interval measured in minutes.
	Interval time.Duration
}

// Keys configures sources of JWK material used to verify token signatures.
// Static and remote sources are merged when both are provided.
type Keys struct {
	// Static is a filesystem path to a JWKS document.
	// If not provided, a remote endpoint must be configured.
	Static string
	// Remote specifies a JWKS endpoint to fetch and refresh keys from.
	// If not provided, a static JWKS file must be configured.
	Remote Remote
}

// Token configures the validation of access tokens.
type Token struct {
	// Keys specifies the JWK source(s) used for signature verification.
	// This setting is required.
	Keys Keys
	// Issuer is the expected value of the "iss" claim.
	// If omitted, the issuer is not validated.
	Issuer string
	// Audience is the value that the "aud" claim is expected to contain.
	// If omitted, the audience is not validated.
	Audience string
	// Leeway is the allowed clock skew interpreted as seconds. Concerns
	// validation of the "exp", "nbf", and "iat" claims. This value is
	// always non-negative.
	Leeway time.Duration
	// Clock allows injecting a custom reference clock for testing purposes.
	Clock jwt.Clock
}

// Rule represents a single, uncompiled authorization rule loaded from config.
// Expressions in When, User, and Roles are plain strings that must be compiled
// before use.
type Rule struct {
	// Deny is true if the rule is a deny rule. Otherwise, the rule is an allow
	// rule.
	Deny bool
	// When specifies the condition under which the rule applies.
	// This expression is mandatory for every rule and must always evaluate to
	// a boolean.
	When string
	// User is an optional expression that determines the CouchDB user name to
	// authenticate as. It is empty when Deny is true. If the expression
	// evaluates to an empty string, the request is forwarded anonymously,
	// provided that Headers.Anonymous is true.
	User string
	// Roles is an optional expression that specifies CouchDB roles for
	// authentication. It is empty when Deny is true. If specified, the
	// expression must return a slice of strings.
	Roles string
}

// config is the wire representation of Config.
type config struct {
	Proxy proxy  `yaml:"proxy"`
	Token token  `yaml:"token"`
	Rules []rule `yaml:"rules"`
}

// validate derives the runtime representation of config.
func (c config) validate() (Config, error) {
	proxy, err := c.Proxy.validate()
	if err != nil {
		return Config{}, fmt.Errorf("proxy.%w", err)
	}
	token, err := c.Token.validate()
	if err != nil {
		return Config{}, fmt.Errorf("token.%w", err)
	}
	if len(c.Rules) == 0 {
		return Config{}, errors.New("rules: at least one rule must be specified")
	}
	rules := make([]Rule, len(c.Rules))
	for i, r := range c.Rules {
		rule, err := r.validate()
		if err != nil {
			return Config{}, fmt.Errorf("rules[%d].%w", i, err)
		}
		rules[i] = rule
	}
	return Config{
		Proxy: proxy,
		Token: token,
		Rules: rules,
	}, nil
}

// proxy is the wire representation of Proxy.
type proxy struct {
	Listen  string  `yaml:"listen"`
	Target  string  `yaml:"target"`
	Headers headers `yaml:"headers"`
}

// validate derives the runtime representation of proxy.
func (p proxy) validate() (Proxy, error) {
	listen := strings.TrimSpace(p.Listen)
	if listen == "" {
		listen = ":8080"
	}
	target := strings.TrimSpace(p.Target)
	if target == "" {
		target = "http://localhost:5984"
	}
	u, err := url.Parse(target)
	if err != nil {
		return Proxy{}, fmt.Errorf("target: invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Proxy{}, fmt.Errorf("target: illegal url scheme %q", u.Scheme)
	}
	headers, err := p.Headers.validate()
	if err != nil {
		return Proxy{}, fmt.Errorf("headers.%w", err)
	}
	return Proxy{
		Listen:  listen,
		Target:  u,
		Headers: headers,
	}, nil
}

// headers is the wire representation of Headers.
type headers struct {
	Signer    signer `yaml:"signer"`
	User      string `yaml:"user"`
	Roles     string `yaml:"roles"`
	Token     string `yaml:"token"`
	Anonymous bool   `yaml:"anonymous"`
}

// validate derives the runtime representation of headers.
func (h headers) validate() (Headers, error) {
	signer, err := h.Signer.validate()
	if err != nil {
		return Headers{}, fmt.Errorf("signer.%w", err)
	}
	user := strings.TrimSpace(h.User)
	if user == "" {
		user = "X-Auth-CouchDB-UserName"
	} else {
		user = http.CanonicalHeaderKey(user)
	}
	roles := strings.TrimSpace(h.Roles)
	if roles == "" {
		roles = "X-Auth-CouchDB-Roles"
	} else {
		roles = http.CanonicalHeaderKey(roles)
	}
	token := strings.TrimSpace(h.Token)
	if token == "" {
		token = "X-Auth-CouchDB-Token"
	} else {
		token = http.CanonicalHeaderKey(token)
	}
	return Headers{
		Signer:    signer,
		User:      user,
		Roles:     roles,
		Token:     token,
		Anonymous: h.Anonymous,
	}, nil
}

// signer is the wire representation of Signer.
type signer struct {
	Secret    string `yaml:"secret"`
	Algorithm string `yaml:"algorithm"`
}

// validate derives the runtime representation of signer.
func (s signer) validate() (Signer, error) {
	key := strings.TrimSpace(s.Secret)
	if key == "" {
		// Fall back to environment variable to facilitate secret management.
		key = strings.TrimSpace(os.Getenv("VOUCH_SECRET"))
	}
	var alg func() hash.Hash
	switch name := strings.ToLower(strings.TrimSpace(s.Algorithm)); name {
	case "":
		alg = nil
	case "sha":
		alg = sha1.New
	case "sha224":
		alg = sha256.New224
	case "sha256":
		alg = sha256.New
	case "sha384":
		alg = sha512.New384
	case "sha512":
		alg = sha512.New
	default:
		return Signer{}, fmt.Errorf("algorithm: unsupported type %q", name)
	}
	return Signer{
		Secret:    key,
		Algorithm: alg,
	}, nil
}

// remote is the wire representation of Remote.
type remote struct {
	Endpoint string `yaml:"endpoint"`
	Interval int64  `yaml:"interval"`
}

// validate derives the runtime representation of remote.
func (r remote) validate() (Remote, error) {
	endpoint := strings.TrimSpace(r.Endpoint)
	if endpoint != "" {
		u, err := url.Parse(endpoint)
		if err != nil {
			return Remote{}, fmt.Errorf("endpoint: invalid url: %w", err)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return Remote{}, fmt.Errorf("endpoint: illegal url scheme %q", u.Scheme)
		}
	}
	interval := r.Interval
	if interval < 0 {
		return Remote{}, errors.New("interval: must be non-negative")
	} else if interval == 0 {
		interval = 30
	}
	return Remote{
		Endpoint: endpoint,
		Interval: time.Duration(interval) * time.Minute,
	}, nil
}

// keys is the wire representation of Keys.
type keys struct {
	Static string `yaml:"static"`
	Remote remote `yaml:"remote"`
}

// validate derives the runtime representation of keys.
func (k keys) validate() (Keys, error) {
	static := strings.TrimSpace(k.Static)
	remote, err := k.Remote.validate()
	if err != nil {
		return Keys{}, fmt.Errorf("remote.%w", err)
	}
	if static == "" && remote.Endpoint == "" {
		return Keys{}, fmt.Errorf("at least one of %q or %q must be set",
			"static", "remote.endpoint",
		)
	}
	return Keys{
		Static: static,
		Remote: remote,
	}, nil
}

// token is the wire representation of Token.
type token struct {
	Keys     keys   `yaml:"keys"`
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
	Leeway   int64  `yaml:"leeway"`
}

// validate derives the runtime representation of token.
func (t token) validate() (Token, error) {
	keys, err := t.Keys.validate()
	if err != nil {
		return Token{}, fmt.Errorf("keys.%w", err)
	}
	leeway := t.Leeway
	if leeway < 0 {
		return Token{}, errors.New("leeway: must be non-negative")
	}
	return Token{
		Keys:     keys,
		Issuer:   strings.TrimSpace(t.Issuer),
		Audience: strings.TrimSpace(t.Audience),
		Leeway:   time.Duration(leeway) * time.Second,
	}, nil
}

// Designates the allowed values of rule.Mode.
const (
	modeAllow = "allow"
	modeDeny  = "deny"
)

// rule is is the wire representation of Rule.
type rule struct {
	Mode  string `yaml:"mode"`
	When  string `yaml:"when"`
	User  string `yaml:"user"`
	Roles string `yaml:"roles"`
}

// validate derives the runtime representation of rule.
func (r rule) validate() (Rule, error) {
	deny := false
	switch strings.ToLower(strings.TrimSpace(r.Mode)) {
	case modeAllow:
	case modeDeny:
		deny = true
	case "":
		return Rule{}, fmt.Errorf("mode: must be specified")
	default:
		return Rule{}, fmt.Errorf("mode: must be %q or %q", modeAllow, modeDeny)
	}
	when := strings.TrimSpace(r.When)
	if when == "" {
		return Rule{}, errors.New("when: expression must be specified")
	}
	user := strings.TrimSpace(r.User)
	if user != "" && deny {
		return Rule{}, fmt.Errorf("user: must not be set in %q mode", modeDeny)
	}
	roles := strings.TrimSpace(r.Roles)
	if roles != "" {
		if deny {
			return Rule{}, fmt.Errorf("roles: must not be set in %q mode", modeDeny)
		}
		if user == "" {
			return Rule{}, errors.New("roles: cannot be set without user")
		}
	}
	return Rule{
		Deny:  deny,
		When:  when,
		User:  user,
		Roles: roles,
	}, nil
}

// Load reads a YAML configuration file from path, decodes into wire types,
// then validates and converts them into a fully populated Config instance.
func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read file %q: %w", path, err)
	}

	var cfg config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse yaml: %w", err)
	}

	return cfg.validate()
}
