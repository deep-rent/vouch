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
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

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

// thumbprint computes a SHA-1 thumbprint of the public key.
func thumbprint(pub *rsa.PublicKey) string {
	h := sha1.New()
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

// captureNext captures the headers from the incoming request and
// marks the handler as called.
func captureNext(headers *http.Header, called *bool) http.HandlerFunc {
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
	uid string
	tid string
	adm bool
}

func NewTokenBuilder(key *rsa.PrivateKey, kid string) *TokenBuilder {
	return &TokenBuilder{
		key: key,
		kid: kid,
		now: time.Now(),
	}
}

func (b *TokenBuilder) At(t time.Time) *TokenBuilder {
	b.now = t
	return b
}

func (b *TokenBuilder) Issuer(iss string) *TokenBuilder {
	b.iss = iss
	return b
}

func (b *TokenBuilder) Audience(aud string) *TokenBuilder {
	b.aud = aud
	return b
}

func (b *TokenBuilder) User(uid string) *TokenBuilder {
	b.uid = uid
	return b
}

func (b *TokenBuilder) Team(tid string) *TokenBuilder {
	b.tid = tid
	return b
}

func (b *TokenBuilder) Admin() *TokenBuilder {
	b.adm = true
	return b
}

func (b *TokenBuilder) Sign(t *testing.T) string {
	t.Helper()
	claims := &Claims{
		UserID: b.uid,
		TeamID: b.tid,
		Admin:  b.adm,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    b.iss,
			Audience:  []string{b.aud},
			IssuedAt:  jwt.NewNumericDate(b.now),
			ExpiresAt: jwt.NewNumericDate(b.now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(b.now.Add(-time.Minute)),
			Subject:   b.uid,
		},
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
	jwks     any
	secret   string
	issuer   string
	audience []string
	lifetime int
	leeway   int
	now      *time.Time
}

func NewMiddlewareBuilder(jwks any) *MiddlewareBuilder {
	return &MiddlewareBuilder{
		jwks:     jwks,
		lifetime: 300,
		leeway:   60,
	}
}

func (b *MiddlewareBuilder) WithProxySecret(secret string) *MiddlewareBuilder {
	b.secret = secret
	return b
}

func (b *MiddlewareBuilder) WithIssuer(iss string) *MiddlewareBuilder {
	b.issuer = iss
	return b
}

func (b *MiddlewareBuilder) WithAudience(aud ...string) *MiddlewareBuilder {
	b.audience = aud
	return b
}

func (b *MiddlewareBuilder) WithLifetime(sec int) *MiddlewareBuilder {
	b.lifetime = sec
	return b
}

func (b *MiddlewareBuilder) WithLeeway(sec int) *MiddlewareBuilder {
	b.leeway = sec
	return b
}

func (b *MiddlewareBuilder) WithNow(now time.Time) *MiddlewareBuilder {
	b.now = &now
	return b
}

func (b *MiddlewareBuilder) Build(t *testing.T, next http.Handler) *Middleware {
	t.Helper()
	config := &Config{
		JWKS:        b.jwks,
		ProxySecret: b.secret,
		Lifetime:    b.lifetime,
		Issuer:      b.issuer,
		Audience:    b.audience,
		Leeway:      b.leeway,
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
	next := captureNext(&seen, &called)

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithLeeway(60).
		WithLifetime(300).
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
		User("jon").
		Admin().
		Sign(t)

	var seen http.Header = make(http.Header)
	var called bool
	next := captureNext(&seen, &called)

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithIssuer("iss").
		WithAudience("aud").
		WithLeeway(60).
		WithLifetime(300).
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
	if got := seen.Get(header); got != "jon" {
		t.Fatalf("%s header = %q", header, got)
	}

	header = "X-Auth-CouchDB-Roles"
	if got := seen.Get(header); got != "_admin" {
		t.Fatalf("%s header = %q", header, got)
	}

	header = "X-Auth-CouchDB-Expires"
	if got := seen.Get(header); got != "" {
		t.Fatalf("%s header was not stripped", header)
	}

	header = "X-Auth-CouchDB-Token"
	if got := seen.Get(header); got != "" {
		t.Fatalf("%s header was not stripped", header)
	}
}

func TestUserAccessAllowed(t *testing.T) {
	gen := generate(t)
	now := time.Unix(1_000_000_000, 0)

	token := NewTokenBuilder(gen.Key, gen.Kid).
		At(now).
		Issuer("iss").
		Audience("aud").
		User("jon").
		Team("doe").
		Sign(t)

	var seen http.Header = make(http.Header)
	var called bool
	next := captureNext(&seen, &called)

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithIssuer("iss").
		WithAudience("aud").
		WithLeeway(60).
		WithLifetime(300).
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/user_jon/_all_docs"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !called {
		t.Fatalf("expected allowed request to pass (code=%d called=%v)", rec.Code, called)
	}

	var header string

	header = "X-Auth-CouchDB-UserName"
	if got := seen.Get(header); got != "jon" {
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
		User("jon").
		Team("doe").
		Sign(t)

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithIssuer("iss").
		WithAudience("aud").
		WithLeeway(60).
		WithLifetime(300).
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
		User("jon").
		Team("doe").
		Sign(t)

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithIssuer("iss").
		WithAudience("aud").
		WithLeeway(60).
		WithLifetime(300).
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
	secret := "12345"
	lifetime := 300

	token := NewTokenBuilder(gen.Key, gen.Kid).
		At(now).
		Issuer("iss").
		Audience("aud").
		User("jon").
		Sign(t)

	var seen http.Header = make(http.Header)
	var called bool
	next := captureNext(&seen, &called)

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithIssuer("iss").
		WithAudience("aud").
		WithProxySecret(secret).
		WithLifetime(lifetime).
		WithLeeway(60).
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/user_jon/_all_docs"
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !called {
		t.Fatalf("expected 200 and next called")
	}

	actExp := seen.Get("X-Auth-CouchDB-Expires")
	if actExp == "" {
		t.Fatalf("missing X-Auth-CouchDB-Expires")
	}

	expExp := now.Add(time.Duration(lifetime) * time.Second).Unix()
	if actExp != strconv.FormatInt(expExp, 10) {
		t.Fatalf("got expires = %s, want %d", actExp, expExp)
	}

	actTok := seen.Get("X-Auth-CouchDB-Token")
	if actTok == "" {
		t.Fatalf("missing X-Auth-CouchDB-Token")
	}

	expTok := createProxyToken([]byte(secret), "jon", "", expExp)
	if actTok != expTok {
		t.Fatalf("got token = %s, want %s", actTok, expTok)
	}
}

func TestIssuerAudienceValidationSuccess(t *testing.T) {
	gen := generate(t)
	now := time.Unix(1_000_000_000, 0)

	valid := NewTokenBuilder(gen.Key, gen.Kid).
		At(now).
		Issuer("valid").
		Audience("valid").
		User("jon").
		Sign(t)

	var called bool
	next := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		called = true
		res.WriteHeader(http.StatusOK)
	})

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithIssuer("valid").
		WithAudience("valid").
		WithLeeway(60).
		WithLifetime(300).
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/user_jon/_all_docs"
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
		User("jon").
		Sign(t)

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := NewMiddlewareBuilder(gen.JWKS()).
		WithIssuer("valid").
		WithAudience("valid").
		WithLeeway(60).
		WithLifetime(300).
		WithNow(now).
		Build(t, next)

	url := "http://couch.example.com/user_jon/_all_docs"
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

	mw := NewMiddlewareBuilder(generate(t).JWKS()).
		WithLeeway(60).
		WithLifetime(300).
		Build(t, next)

	url := "http://couch.example.com/user_jon/_all_docs"
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
