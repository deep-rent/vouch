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

// Config represents the entire configuration for the application.
type Config struct {
	// Proxy configures the proxy server.
	// If omitted, the proxy defaults are used.
	Proxy Proxy `yaml:"proxy,omitempty"`
	// Token configures the validation of access tokens.
	// This option is mandatory.
	Token Token `yaml:"token"`
	// Rules defines the list of authorization rules.
	// The first matching rule decides. At least one rule must be provided.
	Rules []Rule `yaml:"rules"`
}

// Proxy configures the proxy server.
type Proxy struct {
	// Listen is the TCP address for the server to listen on in the form host:port.
	// Defaults to :8080.
	Listen string `yaml:"listen,omitempty"`
	// Target is the URL to which requests are proxied.
	// Defaults to http://localhost:5984.
	Target string `yaml:"target,omitempty"`
	// Headers customizes the proxy headers forwarded to CouchDB.
	// If omitted, the CouchDB defaults are used.
	Headers Headers `yaml:"headers,omitempty"`
}

// Headers customizes the proxy headers forwarded to CouchDB.
type Headers struct {
	// Secret is the CouchDB proxy secret used to sign requests.
	// If omitted, the secret is not used.
	Secret string `yaml:"secret,omitempty"`
	// User is the name of the CouchDB proxy header containing the user's name.
	// Defaults to X-Auth-CouchDB-UserName.
	User string `yaml:"user,omitempty"`
	// Roles is the name of the CouchDB proxy header containing the user's roles.
	// Defaults to X-Auth-CouchDB-Roles.
	Roles string `yaml:"roles,omitempty"`
	// Token is the name of the CouchDB proxy header containing the signed token.
	// Defaults to X-Auth-CouchDB-Token.
	Token string `yaml:"token,omitempty"`
}

// Remote configures the polling behavior for a JWKS endpoint.
type Remote struct {
	// Endpoint is the URL from which the JWKS is retrieved.
	// This option is mandatory.
	Endpoint string `yaml:"endpoint"`
	// Interval is the time to wait between polling the JWKS endpoint (in minutes).
	// Defaults to 30.
	Interval time.Duration `yaml:"interval,omitempty"`
}

// Keys configures the key sources for token validation.
// The static and remote keys will be merged.
type Keys struct {
	// Static specifies a set of JWK objects.
	// If not specified, at least one remote endpoint must be provided.
	Static string `yaml:"static,omitempty"`
	// Remote specifies a set of JWKS endpoints from which keys are fetched.
	// If not specified, at least one static key must be provided.
	Remote Remote `yaml:"remote,omitempty"`
}

// Token configures the validation of access tokens.
type Token struct {
	// Keys specifies the key material used to verify signatures.
	// This option is mandatory.
	Keys Keys `yaml:"keys"`
	// Issuer is the expected value of the "iss" claim.
	// If omitted, the issuer is not validated.
	Issuer string `yaml:"issuer,omitempty"`
	// Audience is the value that the "aud" claim is expected to contain.
	// If omitted, the audience is not validated.
	Audience string `yaml:"audience,omitempty"`
	// Leeway is the amount of time to allow for clock skew (in seconds).
	// Defaults to 0.
	Leeway time.Duration `yaml:"leeway,omitempty"`

	Clock jwt.Clock `yaml:"-"`
}

// Rule represents a single, uncompiled authorization rule.
// It is intended to be unmarshaled from a configuration source, such as YAML.
// The expressions in When, User, and Role are plain strings that must be
// compiled before evaluation.
type Rule struct {
	// Mode indicates whether the rule allows or denies access when matched.
	// Supported values are "allow" and "deny".
	Mode string `yaml:"mode"`
	// When specifies the condition under which the rule applies.
	// This expression is mandatory for every rule and must evaluate to a
	// boolean.
	When string `yaml:"when"`
	// User is an optional expression that determines the CouchDB user to
	// authenticate as. This field is only used in "allow" mode. If specified,
	// the expression must return a string. An empty or missing result will
	// cause the request to be forwarded anonymously. Must be left undefined in
	// "deny" mode.
	User string `yaml:"user,omitempty"`
	// Roles is an optional expression that specifies CouchDB roles for
	// authentication. This field is only used in "allow" mode. The expression
	// must return a string, a comma-separated list of strings, or an array of
	// strings. Must be left undefined in "deny" mode.
	Roles string `yaml:"roles,omitempty"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read file %q: %w", path, err)
	}
	var raw Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("parse yaml: %w", err)
	}

	var headers Headers
	{
		user := raw.Proxy.Headers.User
		if user = strings.TrimSpace(user); user == "" {
			user = "X-Auth-CouchDB-UserName"
		} else {
			user = http.CanonicalHeaderKey(user)
		}
		role := raw.Proxy.Headers.Roles
		if role = strings.TrimSpace(role); role == "" {
			role = "X-Auth-CouchDB-Roles"
		} else {
			role = http.CanonicalHeaderKey(role)
		}
		hash := raw.Proxy.Headers.Token
		if hash = strings.TrimSpace(hash); hash == "" {
			hash = "X-Auth-CouchDB-Token"
		} else {
			hash = http.CanonicalHeaderKey(hash)
		}

		headers = Headers{
			Secret: strings.TrimSpace(raw.Proxy.Headers.Secret),
			User:   user,
			Roles:  role,
			Token:  hash,
		}
	}

	var proxy Proxy
	{
		source := strings.TrimSpace(raw.Proxy.Listen)
		if source == "" {
			source = ":8080"
		}
		target := strings.TrimSpace(raw.Proxy.Target)
		if target == "" {
			target = "http://localhost:5984"
		}

		proxy = Proxy{
			Listen:  source,
			Target:  target,
			Headers: headers,
		}
	}

	var keys Keys
	{
		static := raw.Token.Keys.Static
		remote := raw.Token.Keys.Remote

		endpoint := strings.TrimSpace(remote.Endpoint)
		interval := remote.Interval
		if interval == 0 {
			interval = 30
		}
		if static == "" && endpoint == "" {
			return Config{}, fmt.Errorf(
				"token.keys: %q and/or %q must be set",
				"static", "remote.endpoint",
			)
		}

		keys = Keys{
			Static: static,
			Remote: Remote{
				Endpoint: endpoint,
				Interval: interval * time.Minute,
			},
		}
	}

	var token Token
	{
		leeway := raw.Token.Leeway
		if leeway < 0 {
			return Config{}, errors.New("token.leeway: must be non-negative")
		}
		token = Token{
			Keys:     keys,
			Issuer:   strings.TrimSpace(raw.Token.Issuer),
			Audience: strings.TrimSpace(raw.Token.Audience),
			Leeway:   leeway * time.Second,
		}
	}

	rules := raw.Rules
	if rules == nil {
		rules = make([]Rule, 0)
	}
	if len(rules) == 0 {
		return Config{}, errors.New("rules: at least one rule must be specified")
	}

	return Config{
		Proxy: proxy,
		Token: token,
		Rules: rules,
	}, nil
}
