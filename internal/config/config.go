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
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
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
	// Guard configures authentication and authorization of incoming requests.
	Guard Guard
	Server
}

type visitor struct {
	// Version is the version of the Vouch application.
	Version string
	msgs    []string
	seen    map[string]struct{}
}

// warn collects a list of non-fatal configuration issues.
func (v *visitor) warn(msg string) {
	if v.seen == nil {
		// Lazy initialization.
		v.seen = make(map[string]struct{})
	}
	if _, ok := v.seen[msg]; ok {
		// Skip duplicates warnings.
		return
	}
	v.seen[msg] = struct{}{}
	v.msgs = append(v.msgs, msg)
}

// Server configures the HTTP server and proxy.
type Server struct {
	Local
	Proxy
}

// Local configures the local HTTP server.
type Local struct {
	// Addr is the address the server listens on.
	Addr string
}

// Proxy configures communication with the upstream CouchDB server.
type Proxy struct {
	// Target is the URL of the CouchDB server to proxy requests to.
	Target *url.URL
	// Headers customizes the proxy headers sent to CouchDB.
	Headers Headers
}

// Headers customizes the proxy headers forwarded to CouchDB.
type Headers struct {
	// User  configures the proxy header that carries the CouchDB user name.
	User UserHeader
	// Roles configures the proxy header that carries CouchDB roles.
	Roles RolesHeader
	// Token configures the proxy header that carries the CouchDB token.
	Token TokenHeader
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

// UserHeader configures the proxy header that carries the CouchDB user name.
type UserHeader struct {
	// Name is the proxy header name.
	Name string
	// Anonymous allows forwarding requests without an authenticated user.
	// A request is considered anonymous if the deciding rule does not set
	// a user or if the user expression yields an empty string. If false,
	// such requests are denied with 401 Unauthorized.
	Anonymous bool
}

// RolesHeader configures the proxy header that carries CouchDB roles.
type RolesHeader struct {
	// Name is the proxy header name.
	Name string
	// Default specifies the comma-separated list of default roles to assign to
	// a user if the deciding rule does not set any roles.
	Default string
}

// TokenHeader configures the proxy header that carries the CouchDB token.
type TokenHeader struct {
	// Name is the proxy header name.
	Name string
	Signer
}

// Remote configures periodic retrieval of a JWKS from a remote endpoint.
type Remote struct {
	// Endpoint is the HTTP(S) URL from which the JWKS is retrieved.
	// Required if no static key set is provided.
	Endpoint string
	// Interval is the poll interval measured in minutes.
	Interval time.Duration
	// UserAgent is the User-Agent header value used when making HTTP calls.
	UserAgent string
}

// Guard configures the authentication and authorization of incoming requests.
type Guard struct {
	// Token configures how incoming bearer tokens are validated.
	Token Token
	// Rules defines ordered authorization rules. The first matching rule
	// decides the outcome. At least one rule is required.
	Rules []Rule
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
	// provided that the user header configuration allows anonymous requests.
	User string
	// Roles is an optional expression that specifies CouchDB roles for
	// authentication. It is empty when Deny is true. If specified, the
	// expression must return a slice of strings.
	Roles string
}

// config is the wire representation of Config.
type config struct {
	Local local `yaml:"local"`
	Proxy proxy `yaml:"proxy"`
	Guard guard `yaml:"guard"`
}

// validate derives the runtime representation of config.
func (c config) validate(v *visitor) (Config, error) {
	local, err := c.Local.validate(v)
	if err != nil {
		return Config{}, fmt.Errorf("local.%w", err)
	}
	proxy, err := c.Proxy.validate(v)
	if err != nil {
		return Config{}, fmt.Errorf("proxy.%w", err)
	}
	guard, err := c.Guard.validate(v)
	if err != nil {
		return Config{}, fmt.Errorf("guard.%w", err)
	}
	server := Server{
		Local: local,
		Proxy: proxy,
	}
	return Config{
		Guard:  guard,
		Server: server,
	}, nil
}

// guard is the wire representation of Guard.
type guard struct {
	Token token  `yaml:"token"`
	Rules []rule `yaml:"rules"`
}

// validate derives the runtime representation of guard.
func (g guard) validate(v *visitor) (Guard, error) {
	token, err := g.Token.validate(v)
	if err != nil {
		return Guard{}, fmt.Errorf("token.%w", err)
	}
	if len(g.Rules) == 0 {
		return Guard{}, errors.New("rules: at least one rule must be specified")
	}
	rules := make([]Rule, len(g.Rules))
	for i, r := range g.Rules {
		rule, err := r.validate(v)
		if err != nil {
			return Guard{}, fmt.Errorf("rules[%d].%w", i, err)
		}
		rules[i] = rule
	}
	return Guard{
		Token: token,
		Rules: rules,
	}, nil
}

// local is the wire representation of Local.
type local struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// validate derives the runtime representation of local.
func (l local) validate(_ *visitor) (Local, error) {
	host := strings.TrimSpace(l.Host)
	port := l.Port
	if port < 0 || port > 65535 {
		return Local{}, errors.New("port: out of range")
	}
	if port == 0 {
		port = 8080
	}
	return Local{
		Addr: net.JoinHostPort(host, strconv.Itoa(port)),
	}, nil
}

// proxy is the wire representation of Proxy.
type proxy struct {
	Scheme  string  `yaml:"scheme"`
	Host    string  `yaml:"host"`
	Port    int     `yaml:"port"`
	Headers headers `yaml:"headers"`
}

// validate derives the runtime representation of proxy.
func (p proxy) validate(v *visitor) (Proxy, error) {
	scheme := strings.TrimSpace(p.Scheme)
	if scheme == "" {
		scheme = "http"
	}
	host := strings.TrimSpace(p.Host)
	if host == "" {
		host = "localhost"
	}
	port := p.Port
	if port < 0 || port > 65535 {
		return Proxy{}, errors.New("port: out of range")
	}
	if port == 0 {
		port = 8080
	}
	u, err := url.Parse(fmt.Sprintf("%s://%s:%d", scheme, host, port))
	if err != nil {
		return Proxy{}, fmt.Errorf("scheme+host+port: invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return Proxy{}, fmt.Errorf("scheme: must be 'http' or 'https'")
	}
	headers, err := p.Headers.validate(v)
	if err != nil {
		return Proxy{}, fmt.Errorf("headers.%w", err)
	}
	return Proxy{
		Target:  u,
		Headers: headers,
	}, nil
}

// headers is the wire representation of Headers.
type headers struct {
	User  userHeader  `yaml:"user"`
	Roles rolesHeader `yaml:"roles"`
	Token tokenHeader `yaml:"token"`
}

// validate derives the runtime representation of headers.
func (h headers) validate(v *visitor) (Headers, error) {
	user, err := h.User.validate(v)
	if err != nil {
		return Headers{}, fmt.Errorf("user.%w", err)
	}
	roles, err := h.Roles.validate(v)
	if err != nil {
		return Headers{}, fmt.Errorf("roles.%w", err)
	}
	token, err := h.Token.validate(v)
	if err != nil {
		return Headers{}, fmt.Errorf("token.%w", err)
	}
	return Headers{
		User:  user,
		Roles: roles,
		Token: token,
	}, nil
}

// userHeader is the wire representation of UserHeader.
type userHeader struct {
	Name      string `yaml:"name"`
	Anonymous bool   `yaml:"anonymous"`
}

// validate derives the runtime representation of userHeader.
func (u userHeader) validate(_ *visitor) (UserHeader, error) {
	name := strings.TrimSpace(u.Name)
	if name == "" {
		name = "X-Auth-CouchDB-UserName"
	} else {
		name = http.CanonicalHeaderKey(name)
	}
	return UserHeader{
		Name:      name,
		Anonymous: u.Anonymous,
	}, nil
}

// rolesHeader is the wire representation of RolesHeader.
type rolesHeader struct {
	Name    string   `yaml:"name"`
	Default []string `yaml:"default"`
}

// validate derives the runtime representation of rolesHeader.
func (r rolesHeader) validate(_ *visitor) (RolesHeader, error) {
	name := strings.TrimSpace(r.Name)
	if name == "" {
		name = "X-Auth-CouchDB-Roles"
	} else {
		name = http.CanonicalHeaderKey(name)
	}
	defs := make([]string, 0, len(r.Default))
	for _, r := range r.Default {
		r = strings.TrimSpace(r)
		if r != "" {
			defs = append(defs, r)
		}
	}
	return RolesHeader{
		Name:    name,
		Default: strings.Join(defs, ","),
	}, nil
}

// tokenHeader is the wire representation of TokenHeader.
type tokenHeader struct {
	Name   string `yaml:"name"`
	signer `yaml:",inline"`
}

// validate derives the runtime representation of tokenHeader.
func (t tokenHeader) validate(v *visitor) (TokenHeader, error) {
	name := strings.TrimSpace(t.Name)
	if name == "" {
		name = "X-Auth-CouchDB-Token"
	} else {
		name = http.CanonicalHeaderKey(name)
	}
	s, err := t.signer.validate(v)
	if err != nil {
		return TokenHeader{}, fmt.Errorf("signer.%w", err)
	}
	return TokenHeader{
		Name:   name,
		Signer: s,
	}, nil
}

// signer is the wire representation of Signer.
type signer struct {
	Secret    string `yaml:"secret"`
	Algorithm string `yaml:"algorithm"`
}

// validate derives the runtime representation of signer.
func (s signer) validate(v *visitor) (Signer, error) {
	key := strings.TrimSpace(s.Secret)
	if key == "" {
		// Fall back to environment variable to facilitate secret management.
		key = strings.TrimSpace(os.Getenv("VOUCH_SECRET"))
	}
	if key == "" {
		v.warn("proxy signing is disabled; this is not recommended for production")
	}
	var alg func() hash.Hash
	switch name := strings.ToLower(strings.TrimSpace(s.Algorithm)); name {
	case "":
		alg = nil
	case "sha":
		alg = sha1.New
		v.warn("proxy signing uses sha1; prefer sha256 or stronger")
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
func (r remote) validate(v *visitor) (Remote, error) {
	endpoint := strings.TrimSpace(r.Endpoint)
	if endpoint != "" {
		u, err := url.Parse(endpoint)
		if err != nil {
			return Remote{}, fmt.Errorf("endpoint: invalid url: %w", err)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return Remote{}, fmt.Errorf("endpoint: illegal url scheme %q", u.Scheme)
		} else if u.Scheme != "https" {
			v.warn("jwks endpoint is not using https")
		}
	}
	interval := r.Interval
	if interval < 0 {
		return Remote{}, errors.New("interval: must be non-negative")
	} else if interval == 0 {
		interval = 30
	}
	return Remote{
		Endpoint:  endpoint,
		Interval:  time.Duration(interval) * time.Minute,
		UserAgent: "Vouch/" + v.Version,
	}, nil
}

// keys is the wire representation of Keys.
type keys struct {
	Static string `yaml:"static"`
	Remote remote `yaml:"remote"`
}

// validate derives the runtime representation of keys.
func (k keys) validate(v *visitor) (Keys, error) {
	static := strings.TrimSpace(k.Static)
	remote, err := k.Remote.validate(v)
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
func (t token) validate(v *visitor) (Token, error) {
	keys, err := t.Keys.validate(v)
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

// rule is the wire representation of Rule.
type rule struct {
	Mode  string `yaml:"mode"`
	When  string `yaml:"when"`
	User  string `yaml:"user"`
	Roles string `yaml:"roles"`
}

// validate derives the runtime representation of rule.
func (r rule) validate(_ *visitor) (Rule, error) {
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

// LoadOptions holds options for the Load function.
type LoadOptions struct {
	// Version is the Vouch application version.
	// Defaults to "dev".
	Version string
}

// LoadOption influences Load behavior.
type LoadOption func(*LoadOptions)

// WithVersion sets the Vouch application version.
func WithVersion(v string) LoadOption {
	return func(o *LoadOptions) { o.Version = strings.TrimSpace(v) }
}

// Load reads a YAML configuration file from path, decodes into wire types,
// then validates and converts them into a fully populated Config instance.
func Load(path string, opts ...LoadOption) (Config, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, nil, fmt.Errorf("read file %q: %w", path, err)
	}
	var cfg config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, nil, fmt.Errorf("parse yaml: %w", err)
	}
	// Apply options with defaults.
	o := LoadOptions{
		Version: "dev",
	}
	for _, opt := range opts {
		opt(&o)
	}
	v := &visitor{
		Version: o.Version,
	}
	c, err := cfg.validate(v)
	// Provide warnings even when validation fails to aid diagnosis.
	sort.Strings(v.msgs)
	if err != nil {
		return Config{}, v.msgs, fmt.Errorf("validation: %w", err)
	}
	return c, v.msgs, nil
}
