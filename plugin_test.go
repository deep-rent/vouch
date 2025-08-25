package traefikplugincouchdb

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func base64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func intToBytes(v int64) []byte {
	if v == 0 {
		return []byte{0}
	}
	out := make([]byte, 0, 8)
	for v > 0 {
		out = append([]byte{byte(v & 0xff)}, out...)
		v >>= 8
	}
	return out
}

func toJWKS(key *rsa.PublicKey, kid string) string {
	set := JWKS{
		Keys: []JWK{{
			Kty: "RSA",
			Kid: kid,
			Use: "sig",
			Alg: "RS256",
			N:   base64url(key.N.Bytes()),
			E:   base64url(intToBytes(int64(key.E))),
		}},
	}
	b, _ := json.Marshal(set)
	return string(b)
}

func generate(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	return key
}

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
	jwks     string
	secret   string
	issuer   string
	audience []string
	lifetime int
	leeway   int
	now      *time.Time
}

func NewMiddlewareBuilder(jwks string) *MiddlewareBuilder {
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

func captureNext(headers *http.Header, called *bool) http.HandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		*called = true
		for k := range req.Header {
			headers.Set(k, req.Header.Get(k))
		}
		res.WriteHeader(http.StatusOK)
	}
}

func proxyToken(secret []byte, username, roles string, expires int64) string {
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write([]byte(username + "," + roles + "," + strconv.FormatInt(expires, 10)))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestOptionsBypass(t *testing.T) {
	key := generate(t)
	kid := "abc"
	now := time.Unix(1_700_000_000, 0)
	jwks := toJWKS(&key.PublicKey, kid)

	var seen http.Header = make(http.Header)
	var called bool
	next := captureNext(&seen, &called)

	mw := NewMiddlewareBuilder(jwks).
		WithLeeway(60).
		WithLifetime(300).
		WithNow(now).
		Build(t, next)

	req := httptest.NewRequest(http.MethodOptions, "http://host.domain/db/_all_docs", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if !called {
		t.Fatalf("next not called for OPTIONS")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if seen.Get("X-Auth-CouchDB-UserName") != "" {
		t.Fatalf("unexpected proxy headers on OPTIONS")
	}
}

func TestAdminAccessSetsAdminRoleAndStripsAuth(t *testing.T) {
	key := generate(t)
	kid := "abc"
	now := time.Unix(1_700_000_000, 0)
	jwks := toJWKS(&key.PublicKey, kid)

	token := NewTokenBuilder(key, kid).
		At(now).
		Issuer("iss").
		Audience("aud").
		User("jon").
		Admin().
		Sign(t)

	var seen http.Header = make(http.Header)
	var called bool
	next := captureNext(&seen, &called)

	mw := NewMiddlewareBuilder(jwks).
		WithIssuer("iss").
		WithAudience("aud").
		WithLeeway(60).
		WithLifetime(300).
		WithNow(now).
		Build(t, next)

	req := httptest.NewRequest(http.MethodGet, "http://host.domain/db/_all_docs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !called {
		t.Fatalf("next not called")
	}
	if got := seen.Get("Authorization"); got != "" {
		t.Fatalf("Authorization header was not stripped")
	}
	if got := seen.Get("X-Auth-CouchDB-UserName"); got != "jon" {
		t.Fatalf("username header = %q", got)
	}
	if got := seen.Get("X-Auth-CouchDB-Roles"); got != "_admin" {
		t.Fatalf("roles header = %q, want _admin", got)
	}
	if seen.Get("X-Auth-CouchDB-Expires") != "" || seen.Get("X-Auth-CouchDB-Token") != "" {
		t.Fatalf("did not expect proxy secret headers without secret")
	}
}

func TestUserAccessAllowedAndDenied(t *testing.T) {
	key := generate(t)
	kid := "abc"
	now := time.Unix(1_700_000_000, 0)
	jwks := toJWKS(&key.PublicKey, kid)

	token := NewTokenBuilder(key, kid).
		At(now).
		Issuer("iss").
		Audience("aud").
		User("jon").
		Team("doe").
		Sign(t)

	// Allowed: user_jon
	{
		var seen http.Header = make(http.Header)
		var called bool
		next := captureNext(&seen, &called)

		mw := NewMiddlewareBuilder(jwks).
			WithIssuer("iss").
			WithAudience("aud").
			WithLeeway(60).
			WithLifetime(300).
			WithNow(now).
			Build(t, next)

		req := httptest.NewRequest(http.MethodGet, "http://host.domain/user_jon/_all_docs", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()

		mw.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK || !called {
			t.Fatalf("expected allowed request to pass (code=%d called=%v)", rec.Code, called)
		}
		if got := seen.Get("X-Auth-CouchDB-UserName"); got != "jon" {
			t.Fatalf("username header = %q", got)
		}
		if got := seen.Get("X-Auth-CouchDB-Roles"); got != "" {
			t.Fatalf("roles header = %q, want empty", got)
		}
	}

	// Denied: other database
	{
		var called bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})

		mw := NewMiddlewareBuilder(jwks).
			WithIssuer("iss").
			WithAudience("aud").
			WithLeeway(60).
			WithLifetime(300).
			WithNow(now).
			Build(t, next)

		req := httptest.NewRequest(http.MethodGet, "http://host.domain/any/_all_docs", nil)
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
}

func TestProxySecretSigning(t *testing.T) {
	key := generate(t)
	kid := "abc"
	now := time.Unix(1_700_000_000, 0)
	jwks := toJWKS(&key.PublicKey, kid)
	secret := "12345"
	lifetime := 300

	token := NewTokenBuilder(key, kid).
		At(now).
		Issuer("iss").
		Audience("aud").
		User("jon").
		Sign(t)

	var seen http.Header = make(http.Header)
	var called bool
	next := captureNext(&seen, &called)

	mw := NewMiddlewareBuilder(jwks).
		WithIssuer("iss").
		WithAudience("aud").
		WithProxySecret(secret).
		WithLifetime(lifetime).
		WithLeeway(60).
		WithNow(now).
		Build(t, next)

	req := httptest.NewRequest(http.MethodGet, "http://host.domain/user_jon/_all_docs", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK || !called {
		t.Fatalf("expected 200 and next called")
	}

	gotExp := seen.Get("X-Auth-CouchDB-Expires")
	if gotExp == "" {
		t.Fatalf("missing X-Auth-CouchDB-Expires")
	}

	wantExp := now.Add(time.Duration(lifetime) * time.Second).Unix()
	if gotExp != strconv.FormatInt(wantExp, 10) {
		t.Fatalf("expires = %s, want %d", gotExp, wantExp)
	}

	gotTok := seen.Get("X-Auth-CouchDB-Token")
	if gotTok == "" {
		t.Fatalf("missing X-Auth-CouchDB-Token")
	}

	wantTok := proxyToken([]byte(secret), "jon", "", wantExp)
	if gotTok != wantTok {
		t.Fatalf("token = %s, want %s", gotTok, wantTok)
	}
}

func TestIssuerAudienceValidation(t *testing.T) {
	key := generate(t)
	kid := "abc"
	now := time.Unix(1_700_000_000, 0)
	jwks := toJWKS(&key.PublicKey, kid)

	valid := NewTokenBuilder(key, kid).
		At(now).
		Issuer("issuer-ok").
		Audience("aud-ok").
		User("jon").
		Sign(t)

	invalid := NewTokenBuilder(key, kid).
		At(now).
		Issuer("issuer-ok").
		Audience("aud-bad").
		User("jon").
		Sign(t)

	t.Run("valid", func(t *testing.T) {
		var called bool
		next := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			called = true
			res.WriteHeader(http.StatusOK)
		})

		mw := NewMiddlewareBuilder(jwks).
			WithIssuer("issuer-ok").
			WithAudience("aud-ok").
			WithLeeway(60).
			WithLifetime(300).
			WithNow(now).
			Build(t, next)

		req := httptest.NewRequest(http.MethodGet, "http://host.domain/user_jon/_all_docs", nil)
		req.Header.Set("Authorization", "Bearer "+valid)
		rec := httptest.NewRecorder()

		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !called {
			t.Fatalf("expected valid token to pass")
		}
	})

	t.Run("invalid", func(t *testing.T) {
		var called bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})

		mw := NewMiddlewareBuilder(jwks).
			WithIssuer("issuer-ok").
			WithAudience("aud-ok").
			WithLeeway(60).
			WithLifetime(300).
			WithNow(now).
			Build(t, next)

		req := httptest.NewRequest(http.MethodGet, "http://host.domain/user_jon/_all_docs", nil)
		req.Header.Set("Authorization", "Bearer "+invalid)
		rec := httptest.NewRecorder()

		mw.ServeHTTP(rec, req)
		if called {
			t.Fatalf("next should not be called for invalid token")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got == "" {
			t.Fatalf("expected WWW-Authenticate header")
		}
	})
}

func TestMissingAuthorizationHeader(t *testing.T) {
	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	key := generate(t)
	kid := "abc"
	jwks := toJWKS(&key.PublicKey, kid)

	mw := NewMiddlewareBuilder(jwks).
		WithLeeway(60).
		WithLifetime(300).
		Build(t, next)

	req := httptest.NewRequest(http.MethodGet, "http://host.domain/user_jon/_all_docs", nil)
	rec := httptest.NewRecorder()

	mw.ServeHTTP(rec, req)

	if called {
		t.Fatalf("next should not be called")
	}

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	if got := rec.Header().Get("WWW-Authenticate"); got == "" {
		t.Fatalf("expected WWW-Authenticate header")
	}
}
