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

package traefikplugincouchdb

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deep-rent/traefik-plugin-couchdb/auth"
	"github.com/golang-jwt/jwt/v5"
)

// --- HELPERS ---

// JWK represents an RSA JSON Web Key.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// base64url encodes a byte slice in Base64URL.
func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// bytes converts an integer to a big-endian byte slice without
// leading zero bytes.
func bytes(n int64) []byte {
	if n == 0 {
		return []byte{0}
	}
	b := make([]byte, 0, 8)
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return b
}

// thumbprint calculates a SHA-256 thumbprint of the public key.
func thumbprint(pub *rsa.PublicKey) string {
	h := sha256.New()
	_, _ = h.Write(pub.N.Bytes())
	_, _ = h.Write(bytes(int64(pub.E)))
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// GeneratedKey represents a generated RSA key pair.
type GeneratedKey struct {
	Key *rsa.PrivateKey
	Kid string
	JWK JWK
}

// JWKS produces a JWKS that contains this key as the only element.
func (t *GeneratedKey) JWKS() JWKS {
	return JWKS{
		Keys: []JWK{t.JWK},
	}
}

// generate creates a new RSA key pair and returns it.
func generate(t *testing.T) *GeneratedKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	pub := &key.PublicKey
	kid := thumbprint(pub)
	return &GeneratedKey{
		Key: key,
		Kid: kid,
		JWK: JWK{
			Kty: "RSA",
			Kid: kid,
			Use: "sig",
			Alg: "RS256",
			N:   base64url(pub.N.Bytes()),
			E:   base64url(bytes(int64(pub.E))),
		},
	}
}

// trap captures the headers from the incoming request and
// marks the handler as called.
func trap(headers *http.Header, called *bool) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		*called = true
		for k := range req.Header {
			headers.Set(k, req.Header.Get(k))
		}
		res.WriteHeader(http.StatusOK)
	}
}

// --- BUILDERS ---

type TokenBuilder struct {
	key *rsa.PrivateKey
	kid string
	now time.Time
	iss string
	aud string
	sub string
	adm bool
}

func NewTokenBuilder(key *rsa.PrivateKey, kid string) *TokenBuilder {
	return &TokenBuilder{
		key: key,
		kid: kid,
		now: time.Now(),
	}
}

func (b *TokenBuilder) At(now time.Time) *TokenBuilder    { b.now = now; return b }
func (b *TokenBuilder) Issuer(iss string) *TokenBuilder   { b.iss = iss; return b }
func (b *TokenBuilder) Audience(aud string) *TokenBuilder { b.aud = aud; return b }
func (b *TokenBuilder) Subject(sub string) *TokenBuilder  { b.sub = sub; return b }
func (b *TokenBuilder) Admin() *TokenBuilder              { b.adm = true; return b }

func (b *TokenBuilder) Sign(t *testing.T) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": b.iss,
		"aud": b.aud,
		"sub": b.sub,
		"iat": jwt.NewNumericDate(b.now),
		"exp": jwt.NewNumericDate(b.now.Add(time.Hour)),
		"nbf": jwt.NewNumericDate(b.now.Add(-time.Minute)),
	}
	if b.adm {
		claims["adm"] = true
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = b.kid
	signed, err := token.SignedString(b.key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

type MiddlewareBuilder struct {
	jwks   any
	secret string
	iss    string
	aud    string
	leeway int
	now    *time.Time
	rules  []auth.Rule
}

func NewMiddlewareBuilder(jwks any) *MiddlewareBuilder {
	return &MiddlewareBuilder{
		jwks:   jwks,
		leeway: 60,
	}
}

func (b *MiddlewareBuilder) WithSecret(secret string) *MiddlewareBuilder { b.secret = secret; return b }
func (b *MiddlewareBuilder) WithIssuer(iss string) *MiddlewareBuilder    { b.iss = iss; return b }
func (b *MiddlewareBuilder) WithAudience(aud string) *MiddlewareBuilder  { b.aud = aud; return b }
func (b *MiddlewareBuilder) WithLeeway(sec int) *MiddlewareBuilder       { b.leeway = sec; return b }
func (b *MiddlewareBuilder) WithNow(now time.Time) *MiddlewareBuilder    { b.now = &now; return b }
func (b *MiddlewareBuilder) WithRules(rules ...auth.Rule) *MiddlewareBuilder {
	b.rules = rules
	return b
}

func (b *MiddlewareBuilder) Build(t *testing.T, next http.Handler) *Middleware {
	t.Helper()
	config := &Config{
		JWKS:     b.jwks,
		Secret:   b.secret,
		Issuer:   b.iss,
		Audience: b.aud,
		Leeway:   b.leeway,
		Rules:    b.rules,
	}
	h, err := New(context.Background(), next, config, "test")
	if err != nil {
		t.Fatalf("create middleware: %v", err)
	}
	mw, ok := h.(*Middleware)
	if !ok {
		t.Fatalf("expected *Middleware, got %T", h)
	}
	if b.now != nil {
		mw.now = func() time.Time { return *b.now }
	}
	return mw
}

// --- TESTS ---

func TestOptionsBypass(t *testing.T) {
	gen := generate(t)
	now := time.Unix(1_000_000_000, 0)

	var seen http.Header = make(http.Header)
	var called bool
	next := trap(&seen, &called)

	// Rules won't be used for OPTIONS; still provide a minimal allow to satisfy config.
	rules := []auth.Rule{
		{Mode: "allow", When: "true", User: `"anon"`, Role: `""`},
	}

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithRules(rules...).
		WithLeeway(60).
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/db/_all_docs"
	req := httptest.NewRequest(http.MethodOptions, url, nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("next not called for OPTIONS")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	header := "X-Auth-CouchDB-UserName"
	if got := seen.Get(header); got != "" {
		t.Fatalf("unexpected proxy headers on OPTIONS")
	}
}

func TestAdminAccess(t *testing.T) {
	gen := generate(t)
	now := time.Unix(1_000_000_000, 0)

	token := NewTokenBuilder(gen.Key, gen.Kid).
		At(now).
		Issuer("iss").
		Audience("aud").
		Subject("bob").
		Admin().
		Sign(t)

	var seen http.Header = make(http.Header)
	var called bool
	next := trap(&seen, &called)

	rules := []auth.Rule{
		{Mode: "allow", When: `C["adm"] == true`, User: `C["sub"]`, Role: `"_admin"`},
	}

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithRules(rules...).
		WithIssuer("iss").
		WithAudience("aud").
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/db/_all_docs"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !called {
		t.Fatalf("next not called")
	}

	var header string

	header = "Authorization"
	if got := seen.Get(header); got != "" {
		t.Fatalf("%s header was not stripped", header)
	}

	header = "X-Auth-CouchDB-UserName"
	if got := seen.Get(header); got != "bob" {
		t.Fatalf("%s header = %q", header, got)
	}

	header = "X-Auth-CouchDB-Roles"
	if got := seen.Get(header); got != "_admin" {
		t.Fatalf("%s header = %q", header, got)
	}

	header = "X-Auth-CouchDB-Expires"
	if got := seen.Get(header); got != "" {
		t.Fatalf("%s header was not set only when proxy secret is enabled", header)
	}

	header = "X-Auth-CouchDB-Token"
	if got := seen.Get(header); got != "" {
		t.Fatalf("%s header was not set only when proxy secret is enabled", header)
	}
}

func TestUserAccessAllowed(t *testing.T) {
	gen := generate(t)
	now := time.Unix(1_000_000_000, 0)

	token := NewTokenBuilder(gen.Key, gen.Kid).
		At(now).
		Issuer("iss").
		Audience("aud").
		Subject("bob").
		Sign(t)

	var seen http.Header = make(http.Header)
	var called bool
	next := trap(&seen, &called)

	rules := []auth.Rule{
		{Mode: "allow",
			When: `DB == "user_"+C["sub"]`,
			User: `C["sub"]`,
			Role: `""`,
		},
	}

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithRules(rules...).
		WithIssuer("iss").
		WithAudience("aud").
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/user_bob/_all_docs"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !called {
		t.Fatalf("expected allowed request to pass (code=%d called=%v)", rec.Code, called)
	}

	var header string

	header = "X-Auth-CouchDB-UserName"
	if got := seen.Get(header); got != "bob" {
		t.Fatalf("%s header = %q", header, got)
	}

	header = "X-Auth-CouchDB-Roles"
	if got := seen.Get(header); got != "" {
		t.Fatalf("%s header = %q, want empty", header, got)
	}
}

func TestUserAccessDenied(t *testing.T) {
	gen := generate(t)
	now := time.Unix(1_000_000_000, 0)

	token := NewTokenBuilder(gen.Key, gen.Kid).
		At(now).
		Issuer("iss").
		Audience("aud").
		Subject("bob").
		Sign(t)

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	rules := []auth.Rule{
		{Mode: "allow",
			When: `DB == "user_"+C["sub"]`,
			User: `C["sub"]`,
			Role: `""`,
		},
	}

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithRules(rules...).
		WithIssuer("iss").
		WithAudience("aud").
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/any/_all_docs"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if called {
		t.Fatalf("next should not be called for forbidden")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestURLWithoutDatabase(t *testing.T) {
	gen := generate(t)
	now := time.Unix(1_000_000_000, 0)

	token := NewTokenBuilder(gen.Key, gen.Kid).
		At(now).
		Issuer("iss").
		Audience("aud").
		Subject("bob").
		Sign(t)

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	rules := []auth.Rule{
		{Mode: "allow",
			When: `DB == "user_"+C["sub"]`,
			User: `C["sub"]`,
			Role: `""`,
		},
	}

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithRules(rules...).
		WithIssuer("iss").
		WithAudience("aud").
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if called {
		t.Fatalf("next should not be called for forbidden")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestProxySecretSigning(t *testing.T) {
	gen := generate(t)
	now := time.Unix(1_000_000_000, 0)

	token := NewTokenBuilder(gen.Key, gen.Kid).
		At(now).
		Issuer("iss").
		Audience("aud").
		Subject("bob").
		Sign(t)

	var seen http.Header = make(http.Header)
	var called bool
	next := trap(&seen, &called)

	rules := []auth.Rule{
		{Mode: "allow", When: `DB == "user_"+C["sub"]`, User: `C["sub"]`, Role: `""`},
	}

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithRules(rules...).
		WithIssuer("iss").
		WithAudience("aud").
		WithSecret("12345").
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/user_bob/_all_docs"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !called {
		t.Fatalf("expected 200 and next called")
	}

	act := seen.Get("X-Auth-CouchDB-Token")
	if act == "" {
		t.Fatalf("missing X-Auth-CouchDB-Token")
	}

	exp := mw.sign("bob")
	if act != exp {
		t.Fatalf("got token = %s, want %s", act, exp)
	}
}

func TestIssuerAudienceValidationSuccess(t *testing.T) {
	gen := generate(t)
	now := time.Unix(1_000_000_000, 0)

	valid := NewTokenBuilder(gen.Key, gen.Kid).
		At(now).
		Issuer("valid").
		Audience("valid").
		Subject("bob").
		Sign(t)

	var called bool
	next := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		called = true
		res.WriteHeader(http.StatusOK)
	})

	rules := []auth.Rule{
		{Mode: "allow", When: `true`, User: `C["sub"]`, Role: `""`},
	}

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithRules(rules...).
		WithIssuer("valid").
		WithAudience("valid").
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/user_bob/_all_docs"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+valid)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !called {
		t.Fatalf("expected valid token to pass")
	}
}

func TestIssuerAudienceValidationFailure(t *testing.T) {
	gen := generate(t)
	now := time.Unix(1_000_000_000, 0)

	invalid := NewTokenBuilder(gen.Key, gen.Kid).
		At(now).
		Issuer("valid").
		Audience("invalid").
		Subject("bob").
		Sign(t)

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	rules := []auth.Rule{
		{Mode: "allow", When: `true`, User: `C["sub"]`, Role: `""`},
	}

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithRules(rules...).
		WithIssuer("valid").
		WithAudience("valid").
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/user_bob/_all_docs"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+invalid)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)
	if called {
		t.Fatalf("next should not be called for invalid token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	header := "WWW-Authenticate"
	if got := rec.Header().Get(header); got == "" {
		t.Fatalf("expected %s header", header)
	}
}

func TestMissingAuthorizationHeader(t *testing.T) {
	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	rules := []auth.Rule{
		{Mode: "allow", When: `true`, User: `"anonymous"`, Role: `""`},
	}

	mw := NewMiddlewareBuilder(generate(t).JWKS()).
		WithRules(rules...).
		Build(t, next)

	url := "http://couch.example.com/user_bob/_all_docs"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if called {
		t.Fatalf("next should not be called")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	header := "WWW-Authenticate"
	if got := rec.Header().Get(header); got == "" {
		t.Fatalf("expected %s header", header)
	}
}

func TestRemoteJWKS(t *testing.T) {
	gen := generate(t)
	now := time.Unix(1_000_000_000, 0)

	// Serve the JWKS over HTTP.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" && r.URL.Path != "/jwks.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gen.JWKS())
	}))
	defer ts.Close()

	// Issue a token that matches the served JWKS.
	token := NewTokenBuilder(gen.Key, gen.Kid).
		At(now).
		Issuer("iss").
		Audience("aud").
		Subject("bob").
		Sign(t)

	var seen http.Header = make(http.Header)
	var called bool
	next := trap(&seen, &called)

	rules := []auth.Rule{
		{Mode: "allow", When: `true`, User: `C["sub"]`, Role: `""`},
	}

	// Configure the middleware to fetch JWKS from the remote URL.
	mw := NewMiddlewareBuilder(ts.URL).
		WithRules(rules...).
		WithIssuer("iss").
		WithAudience("aud").
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/user_bob/_all_docs"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !called {
		t.Fatalf("expected 200 and next called; code=%d called=%v", rec.Code, called)
	}
}
