// Copyright (c) 2025-present deep.rent GmbH (https://www.deep.rent)
// All rights reserved.
//
// This source code is proprietary and confidential. Unauthorized copying, via
// any medium is strictly prohibited.

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
	"net/url"
	"strings"
	"time"

	keyfunc "github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
)

// Config holds the plugin configuration.
type Config struct {
	// JWKS can be:
	// - a string containing a URL (http/https) to a remote JWKS
	// - a string containing raw JWKS JSON
	// - any JSON object/array representing a JWKS (will be marshaled)
	JWKS any `json:"jwks"`

	// ProxySecret enables CouchDB proxy secret signing when set (recommended).
	ProxySecret string `json:"proxySecret,omitempty"`

	// Lifetime controls the expiration time offset (in seconds) of the CouchDB proxy token. Defaults to 300.
	Lifetime int `json:"lifetime,omitempty"`

	// Expected issuer for JWT validation hardening (optional).
	Issuer string `json:"issuer,omitempty"`

	// Allowed audiences for JWT validation hardening (optional).
	Audience []string `json:"audience,omitempty"`

	// Allowed clock skew for temporal validity of tokens (in seconds). Defaults to 0.
	Leeway int `json:"leeway,omitempty"`

	// Allowed signature JWAs. Defaults to the RS*, ES*, and PS* families.
	Algorithms []string `json:"algorithms,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		JWKS:        nil,
		ProxySecret: "",
		Lifetime:    300,
		Issuer:      "",
		Audience:    []string{},
		Leeway:      0,
		Algorithms:  []string{},
	}
}

// Claims represents the expected JWT claims.
type Claims struct {
	UserID string `json:"uid"`           // required
	TeamID string `json:"tid,omitempty"` // optional
	Admin  bool   `json:"adm,omitempty"` // optional
	jwt.RegisteredClaims
}

// Middleware is the HTTP middleware.
type Middleware struct {
	next   http.Handler
	name   string
	config *Config
	keys   jwt.Keyfunc
	parser *jwt.Parser
	secret []byte
	ttl    time.Duration
	now    func() time.Time
}

// Ensure Middleware implements http.Handler.
var _ http.Handler = (*Middleware)(nil)

// New creates a new Middleware based on the provided configuration.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}
	if config.JWKS == nil {
		return nil, errors.New("jwks is required")
	}

	// Build the Keyfunc from URL/string/object.
	keys, err := resolve(ctx, config.JWKS)
	if err != nil {
		return nil, fmt.Errorf("load jwks: %w", err)
	}

	ttl := time.Duration(config.Lifetime) * time.Second
	if ttl <= 0 {
		ttl = 300 * time.Second
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

	mw := &Middleware{
		next:   next,
		name:   name,
		config: config,
		keys:   keys,
		secret: []byte(config.ProxySecret),
		ttl:    ttl,
		now:    time.Now,
	}

	opts := []jwt.ParserOption{
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(leeway),
		// Bind to mw.now so tests can override the clock.
		jwt.WithTimeFunc(func() time.Time { return mw.now() }),
		jwt.WithValidMethods(algs),
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

func (m *Middleware) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	// Allow CORS preflight through without authentication.
	if req.Method == http.MethodOptions {
		m.next.ServeHTTP(res, req)
		return
	}

	token, ok := bearer(req.Header.Get("Authorization"))
	if !ok || token == "" {
		res.Header().Set("WWW-Authenticate", `Bearer error="invalid_request"`)
		http.Error(res, "missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	claims := m.parse(token)
	if claims == nil || claims.UserID == "" {
		res.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(res, "invalid token", http.StatusUnauthorized)
		return
	}

	// Authorization against requested database path.
	if !claims.Admin {
		db := database(req.URL.Path)
		if db == "" {
			http.Error(res, "insufficient permissions", http.StatusForbidden)
			return
		}
		allowed := map[string]struct{}{
			"user_" + claims.UserID: {},
			"team_" + claims.UserID: {},
		}
		if claims.TeamID != "" {
			allowed["team_"+claims.TeamID] = struct{}{}
		}
		if _, ok := allowed[db]; !ok {
			http.Error(res, "insufficient permissions", http.StatusForbidden)
			return
		}
	}

	// Always strip the Authorization header.
	req.Header.Del("Authorization")

	// Set CouchDB proxy auth headers (trusted proxy mode).
	username := claims.UserID
	roles := ""
	if claims.Admin {
		roles = "_admin"
	}
	req.Header.Set("X-Auth-CouchDB-UserName", username)
	req.Header.Set("X-Auth-CouchDB-Roles", roles)

	// If a proxy secret is configured, also sign Expires/Token for CouchDB.
	if len(m.secret) > 0 {
		expires := m.now().Add(m.ttl).Unix()
		req.Header.Set("X-Auth-CouchDB-Expires", fmt.Sprintf("%d", expires))

		// Token = hex(HMAC-SHA1(secret, "username,roles,expires"))
		mac := hmac.New(sha1.New, m.secret)
		_, _ = mac.Write([]byte(username + "," + roles + "," + fmt.Sprintf("%d", expires)))
		req.Header.Set("X-Auth-CouchDB-Token", hex.EncodeToString(mac.Sum(nil)))
	}

	// Forward request.
	m.next.ServeHTTP(res, req)
}

// parse parses and validates the JWT using the JWKS keyfunc and allowed algorithms.
func (m *Middleware) parse(token string) *Claims {
	claims := &Claims{}
	result, err := m.parser.ParseWithClaims(token, claims, m.keys)
	if err != nil || result == nil || !result.Valid {
		return nil
	}
	return claims
}

// bearer extracts a bearer token from the Authorization header value.
func bearer(header string) (string, bool) {
	if header == "" {
		return "", false
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	return parts[1], true
}

// database returns the name of the target database by decoding the first non-empty segment of the given URL path.
func database(path string) string {
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	segments := strings.SplitN(path, "/", 3)
	if len(segments) < 2 {
		return ""
	}
	first := segments[1]
	s, err := url.PathUnescape(first)
	if err != nil {
		return first
	}
	return s
}

// isURL determines if a string is a valid HTTP URL.
func isURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "http" || u.Scheme == "https"
}

// resolve returns a key provider from a JWKS value that can be a
// string (URL or raw JSON) or any JSON object/array.
func resolve(ctx context.Context, v any) (jwt.Keyfunc, error) {
	switch t := v.(type) {
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return nil, errors.New("empty jwks string")
		}
		if isURL(s) {
			jwks, err := keyfunc.NewDefaultCtx(ctx, []string{s})
			if err != nil {
				return nil, err
			}
			return jwks.Keyfunc, nil
		}
		jwks, err := keyfunc.NewJWKSetJSON([]byte(s))
		if err != nil {
			return nil, err
		}
		return jwks.Keyfunc, nil

	case []byte:
		if len(t) == 0 {
			return nil, errors.New("empty jwks bytes")
		}
		jwks, err := keyfunc.NewJWKSetJSON(t)
		if err != nil {
			return nil, err
		}
		return jwks.Keyfunc, nil

	case json.RawMessage:
		if len(t) == 0 {
			return nil, errors.New("empty jwks raw message")
		}
		jwks, err := keyfunc.NewJWKSetJSON(t)
		if err != nil {
			return nil, err
		}
		return jwks.Keyfunc, nil

	default:
		// Marshal arbitrary object/array to JSON and treat as JWKS.
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("marshal jwks object: %w", err)
		}
		if len(b) == 0 {
			return nil, errors.New("empty jwks object")
		}
		jwks, err := keyfunc.NewJWKSetJSON(b)
		if err != nil {
			return nil, err
		}
		return jwks.Keyfunc, nil
	}
}
