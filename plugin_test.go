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

// --- Helpers ---

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
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

func jwksFromRSA(pk *rsa.PublicKey, kid string) string {
	j := jwks{
		Keys: []jwk{{
			Kty: "RSA",
			Kid: kid,
			Use: "sig",
			Alg: "RS256",
			N:   base64url(pk.N.Bytes()),
			E:   base64url(intToBytes(int64(pk.E))),
		}},
	}
	b, _ := json.Marshal(j)
	return string(b)
}

func genRSA(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA: %v", err)
	}
	return k
}

func signJWT(t *testing.T, key *rsa.PrivateKey, kid, uid, tid string, admin bool, iss, aud string, now time.Time) string {
	t.Helper()
	claims := &Claims{
		UserID: uid,
		TeamID: tid,
		Admin:  admin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    iss,
			Audience:  []string{aud},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

func makeMiddleware(t *testing.T, next http.Handler, jwks, secret, iss, aud string, lifetime, leeway int) *Middleware {
	t.Helper()
	cfg := &Config{
		JWKS:        jwks,
		ProxySecret: secret,
		Lifetime:    lifetime,
		Issuer:      iss,
		Audience:    aud,
		Leeway:      leeway,
	}
	h, err := New(context.Background(), next, cfg, "test")
	if err != nil {
		t.Fatalf("New middleware: %v", err)
	}
	mw, ok := h.(*Middleware)
	if !ok {
		t.Fatalf("expected *Middleware, got %T", h)
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

// --- Tests ---

func TestOptionsBypass(t *testing.T) {
	priv := genRSA(t)
	kid := "abc"
	now := time.Unix(1_700_000_000, 0)

	jwks := jwksFromRSA(&priv.PublicKey, kid)
	var seen http.Header = make(http.Header)
	var called bool
	next := captureNext(&seen, &called)

	mw := makeMiddleware(t, next, jwks, "", "", "", 300, 60)
	mw.now = func() time.Time { return now }

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
	priv := genRSA(t)
	kid := "abc"
	now := time.Unix(1_700_000_000, 0)
	jwks := jwksFromRSA(&priv.PublicKey, kid)

	token := signJWT(t, priv, kid, "jon", "", true, "iss", "aud", now)

	var seen http.Header = make(http.Header)
	var called bool
	next := captureNext(&seen, &called)

	mw := makeMiddleware(t, next, jwks, "", "iss", "aud", 300, 60)
	mw.now = func() time.Time { return now }

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
	priv := genRSA(t)
	kid := "abc"
	now := time.Unix(1_700_000_000, 0)
	jwks := jwksFromRSA(&priv.PublicKey, kid)

	token := signJWT(t, priv, kid, "jon", "doe", false, "iss", "aud", now)

	{
		var seen http.Header = make(http.Header)
		var called bool
		next := captureNext(&seen, &called)

		mw := makeMiddleware(t, next, jwks, "", "iss", "aud", 300, 60)
		mw.now = func() time.Time { return now }

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

	{
		var called bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})

		mw := makeMiddleware(t, next, jwks, "", "iss", "aud", 300, 60)
		mw.now = func() time.Time { return now }

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
	priv := genRSA(t)
	kid := "abc"
	fixedNow := time.Unix(1_700_000_000, 0)
	jwks := jwksFromRSA(&priv.PublicKey, kid)
	secret := "supersecret"
	lifetime := 300

	token := signJWT(t, priv, kid, "jon", "", false, "iss", "aud", fixedNow)

	var seen http.Header = make(http.Header)
	var called bool
	next := captureNext(&seen, &called)

	mw := makeMiddleware(t, next, jwks, secret, "iss", "aud", lifetime, 60)
	mw.now = func() time.Time { return fixedNow }

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
	wantExp := fixedNow.Add(time.Duration(lifetime) * time.Second).Unix()
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
	priv := genRSA(t)
	kid := "abc"
	now := time.Unix(1_700_000_000, 0)
	jwks := jwksFromRSA(&priv.PublicKey, kid)

	valid := signJWT(t, priv, kid, "jon", "", false, "issuer-ok", "aud-ok", now)
	invalid := signJWT(t, priv, kid, "jon", "", false, "issuer-ok", "aud-bad", now)

	t.Run("valid", func(t *testing.T) {
		var called bool
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})
		mw := makeMiddleware(t, next, jwks, "", "issuer-ok", "aud-ok", 300, 60)
		mw.now = func() time.Time { return now }

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
		mw := makeMiddleware(t, next, jwks, "", "issuer-ok", "aud-ok", 300, 60)
		mw.now = func() time.Time { return now }

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

	priv := genRSA(t)
	kid := "abc"
	jwks := jwksFromRSA(&priv.PublicKey, kid)

	mw := makeMiddleware(t, next, jwks, "", "", "", 300, 60)
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
