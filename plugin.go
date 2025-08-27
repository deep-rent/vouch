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

// Package traefikplugincouchdb provides a Traefik middleware that validates
// JWTs against a JWKS and authorizes requests using ordered rules evaluated
// with expr. When authorized, it sets CouchDB "trusted proxy" headers
// (X-Auth-CouchDB-*) and can optionally sign them with a proxy secret.
package traefikplugincouchdb

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	keys "github.com/MicahParks/keyfunc/v3"
	"github.com/deep-rent/traefik-plugin-couchdb/auth"
	"github.com/golang-jwt/jwt/v5"
)

// Headers configures the CouchDB trusted proxy header names.
type Headers struct {
	// UserName defaults to "X-Auth-CouchDB-UserName".
	UserName string `json:"userName,omitempty"`

	// Roles defaults to "X-Auth-CouchDB-Roles".
	Roles string `json:"roles,omitempty"`

	// Token defaults to "X-Auth-CouchDB-Token".
	Token string `json:"token,omitempty"`
}

// Config holds the plugin configuration.
type Config struct {
	// JWKS can be either a single string or any array of URLs of remote JWKS
	// endpoints, or a JSON object representing a static JWKS. Remote JWKS
	// endpoints will be continuously polled for changes.
	JWKS any `json:"jwks"`

	// Secret enables CouchDB proxy secret signing when set (recommended).
	Secret string `json:"secret,omitempty"`

	// Expected issuer for JWT validation hardening (optional).
	Issuer string `json:"issuer,omitempty"`

	// Allowed audiences for JWT validation hardening (optional).
	Audience []string `json:"audience,omitempty"`

	// When enabled, makes the 'exp' claims required.
	Strict bool `json:"strict,omitempty"`

	// Allowed clock skew for temporal validity of tokens (in seconds).
	// Defaults to 0.
	Leeway int `json:"leeway,omitempty"`

	// Allowed signature JWAs. Defaults to the RS*, ES*, and PS* families.
	Algorithms []string `json:"algorithms,omitempty"`

	// An ordered list of authorization rules. The first matching rule decides.
	Rules []auth.Rule `json:"rules"`

	// Header names for CouchDB trusted proxy. Optional; defaults applied.
	Headers Headers `json:"headers"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		JWKS:       nil,
		Secret:     "",
		Issuer:     "",
		Audience:   []string{},
		Strict:     false,
		Leeway:     0,
		Algorithms: []string{},
		Rules:      []auth.Rule{},
		Headers:    Headers{},
	}
}

// Middleware is the HTTP middleware.
type Middleware struct {
	next    http.Handler
	name    string
	config  *Config
	keys    jwt.Keyfunc
	parser  *jwt.Parser
	secret  []byte
	now     func() time.Time
	guard   *auth.Guard
	headers Headers
}

// Ensure Middleware implements http.Handler.
var _ http.Handler = (*Middleware)(nil)

func (m *Middleware) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	// Allow CORS preflight through without authentication.
	if req.Method == http.MethodOptions {
		m.next.ServeHTTP(res, req)
		return
	}

	token, ok := token(req.Header.Get("Authorization"))
	if !ok || token == "" {
		res.Header().Set("WWW-Authenticate", `Bearer error="invalid_request"`)
		http.Error(res, "missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	claims := m.verify(token)
	if claims == nil {
		res.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(res, "invalid token", http.StatusUnauthorized)
		return
	}

	// Authorization with rules (first match wins).
	env := auth.NewEnvironment(claims, req)
	pass, user, role, err := m.guard.Authorize(req.Context(), env)
	if err != nil {
		http.Error(res, "insufficient permissions", http.StatusForbidden)
		return
	}
	if !pass {
		http.Error(res, "insufficient permissions", http.StatusForbidden)
		return
	}

	// Strip the authorization header from the forwarded request.
	req.Header.Del("Authorization")

	req.Header.Set(m.headers.UserName, user)
	req.Header.Set(m.headers.Roles, role)

	if len(m.secret) > 0 {
		req.Header.Set(m.headers.Token, m.sign(user))
	}

	// Forward request.
	m.next.ServeHTTP(res, req)
}

// sign computes the proxy token as HEX(HMAC-SHA1(secret, user)).
func (m *Middleware) sign(user string) string {
	mac := hmac.New(sha1.New, m.secret)
	_, _ = mac.Write([]byte(user))
	return hex.EncodeToString(mac.Sum(nil))
}

// verify parses and validates the JWT using the JWKS keyfunc and allowed algorithms.
// It returns the payload claims if valid, or nil if invalid.
func (m *Middleware) verify(token string) map[string]any {
	claims := jwt.MapClaims{}
	result, err := m.parser.ParseWithClaims(token, claims, m.keys)
	if err != nil || result == nil || !result.Valid {
		return nil
	}
	return claims
}

// New creates a new HTTP handler based on the provided configuration.
func New(
	ctx context.Context,
	next http.Handler,
	config *Config,
	name string,
) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}
	if config.JWKS == nil {
		return nil, errors.New("jwks is required")
	}
	if len(config.Rules) == 0 {
		return nil, errors.New("rules must be specified")
	}

	if strings.TrimSpace(config.Headers.UserName) == "" {
		config.Headers.UserName = "X-Auth-CouchDB-UserName"
	}
	if strings.TrimSpace(config.Headers.Roles) == "" {
		config.Headers.Roles = "X-Auth-CouchDB-Roles"
	}
	if strings.TrimSpace(config.Headers.Token) == "" {
		config.Headers.Token = "X-Auth-CouchDB-Token"
	}

	keys, err := resolve(ctx, config.JWKS)
	if err != nil {
		return nil, fmt.Errorf("load jwks: %w", err)
	}

	leeway := max(time.Duration(config.Leeway)*time.Second, 0)
	algs := config.Algorithms
	if len(algs) == 0 {
		algs = []string{
			"RS256", "RS384", "RS512",
			"ES256", "ES384", "ES512",
			"PS256", "PS384", "PS512",
		}
	}

	guard, err := auth.NewGuard(config.Rules)
	if err != nil {
		return nil, fmt.Errorf("build guard: %w", err)
	}

	mw := &Middleware{
		next:    next,
		name:    name,
		config:  config,
		keys:    keys,
		secret:  []byte(config.Secret),
		now:     time.Now,
		guard:   guard,
		headers: config.Headers,
	}

	opts := []jwt.ParserOption{
		jwt.WithLeeway(leeway),
		jwt.WithTimeFunc(func() time.Time { return mw.now() }),
		jwt.WithValidMethods(algs),
	}
	if config.Strict {
		opts = append(opts, jwt.WithExpirationRequired())
	}
	if len(config.Audience) > 0 {
		opts = append(opts, jwt.WithAudience(config.Audience...))
	}
	if iss := strings.TrimSpace(config.Issuer); iss != "" {
		opts = append(opts, jwt.WithIssuer(iss))
	}

	mw.parser = jwt.NewParser(opts...)
	return mw, nil
}

// resolve creates a verification key provider from a JWKS configuration value.
func resolve(ctx context.Context, v any) (jwt.Keyfunc, error) {
	switch t := v.(type) {
	case string:
		return resolveRemote(ctx, []string{t})
	case []string:
		return resolveRemote(ctx, t)
	default:
		return resolveStatic(t)
	}
}

// resolveRemote loads a JWKS from the given URLs.
func resolveRemote(ctx context.Context, urls []string) (jwt.Keyfunc, error) {
	k, err := keys.NewDefaultCtx(ctx, urls)
	if err != nil {
		return nil, fmt.Errorf("fetch remote: %w", err)
	}
	return k.Keyfunc, nil
}

// resolveStatic parses a JWKS from raw JSON.
func resolveStatic(data any) (jwt.Keyfunc, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("marshal json object: %w", err)
	}
	k, err := keys.NewJWKSetJSON(b)
	if err != nil {
		return nil, fmt.Errorf("parse static: %w", err)
	}
	return k.Keyfunc, nil
}

// token extracts a bearer token from the Authorization header, if present.
func token(header string) (string, bool) {
	if header == "" {
		return "", false
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}
