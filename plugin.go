package traefikplugincouchdb

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
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
	// JWKS defines the (public) keys used in signature verification.
	JWKS string `json:"jwks"`

	// ProxySecret enables CouchDB proxy secret signing when set (recommended).
	// By default, the proxy secret is not set.
	ProxySecret string `json:"proxySecret,omitempty"`

	// Lifetime controls the expiration time offset (in seconds) of the CouchDB
	// proxy token. Defaults to 300.
	Lifetime int `json:"lifetime,omitempty"`

	// Expected issuer for JWT validation hardening.
	Issuer string `json:"issuer,omitempty"`

	// Expected audience for JWT validation hardening.
	Audience string `json:"audience,omitempty"`

	// Permissible clock skew for temporal validity of tokens (in seconds).
	// Defaults to 60.
	Leeway int `json:"leeway,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		JWKS:        "",
		ProxySecret: "",
		Lifetime:    300,
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
	next    http.Handler
	name    string
	config  *Config
	keys    jwt.Keyfunc
	algs    map[string]struct{}
	methods []string
	parser  *jwt.Parser
	secret  []byte
	ttl     time.Duration
	now     func() time.Time
}

// Ensure Middleware implements http.Handler.
var _ http.Handler = (*Middleware)(nil)

// New creates a new Middleware based on the provided configuration.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}
	if strings.TrimSpace(config.JWKS) == "" {
		return nil, errors.New("jwks is required")
	}

	jwks, err := keyfunc.NewJWKSetJSON([]byte(config.JWKS))
	if err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}

	// Supported algorithms: RSXXX, ESXXX, PSXXX
	algs := map[string]struct{}{
		"RS256": {}, "RS384": {}, "RS512": {},
		"ES256": {}, "ES384": {}, "ES512": {},
		"PS256": {}, "PS384": {}, "PS512": {},
	}
	methods := make([]string, 0, len(algs))
	for a := range algs {
		methods = append(methods, a)
	}

	ttl := time.Duration(config.Lifetime) * time.Second
	if ttl <= 0 {
		ttl = 300 * time.Second
	}
	leeway := time.Duration(config.Leeway) * time.Second
	if leeway < 0 {
		leeway = 0
	}
	if leeway == 0 && config.Leeway == 0 {
		leeway = 60 * time.Second
	}

	parser := jwt.NewParser(
		jwt.WithValidMethods(methods),
		jwt.WithLeeway(leeway),
	)

	return &Middleware{
		next:    next,
		name:    name,
		config:  config,
		keys:    jwks.Keyfunc,
		algs:    algs,
		methods: methods,
		parser:  parser,
		secret:  []byte(config.ProxySecret),
		ttl:     ttl,
		now:     time.Now,
	}, nil
}

func (m *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Allow CORS preflight through without authentication.
	if req.Method == http.MethodOptions {
		m.next.ServeHTTP(rw, req)
		return
	}

	token, ok := bearer(req.Header.Get("Authorization"))
	if !ok || token == "" {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_request"`)
		http.Error(rw, "missing or invalid authorization header", http.StatusUnauthorized)
		return
	}

	claims := m.parse(token)
	if claims == nil || claims.UserID == "" {
		rw.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(rw, "invalid token", http.StatusUnauthorized)
		return
	}

	// Authorization against requested database path.
	if !claims.Admin {
		db := database(req.URL.Path)
		if db == "" {
			http.Error(rw, "insufficient permissions", http.StatusForbidden)
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
			http.Error(rw, "insufficient permissions", http.StatusForbidden)
			return
		}
	}

	// Always strip the Authorization header.
	req.Header.Del("Authorization")

	// Set CouchDB proxy auth headers (trusted proxy mode).
	username := claims.UserID
	roles := ""
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
	m.next.ServeHTTP(rw, req)
}

// parse parses and validates the JWT using the JWKS keyfunc and allowed algorithms.
func (m *Middleware) parse(token string) *Claims {
	claims := &Claims{}
	result, err := m.parser.ParseWithClaims(token, claims, m.keys)
	if err != nil || result == nil || !result.Valid {
		return nil
	}
	// Enforce supported algorithms.
	if _, ok := m.algs[result.Method.Alg()]; !ok {
		return nil
	}
	// Optional issuer/audience checks.
	if iss := strings.TrimSpace(m.config.Issuer); iss != "" && claims.Issuer != iss {
		return nil
	}
	if aud := strings.TrimSpace(m.config.Audience); aud != "" && !has(claims.Audience, aud) {
		return nil
	}
	return claims
}

// allowed checks if the given algorithm is allowed for signature verification.
func (m *Middleware) allowed(alg string) bool {
	_, ok := m.algs[alg]
	return ok
}

// has returns true if the wanted audience is present.
func has(list jwt.ClaimStrings, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
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

// database returns the name of the target database by decoding the first
// non-empty segment of the given URL path.
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
