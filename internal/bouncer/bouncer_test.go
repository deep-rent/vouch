package bouncer_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBouncer_Bounce(t *testing.T) {
	secretKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyID := "test"

	sharedKey := jwk.NewKeyBuilder(jwa.ES256).
		WithKeyID(keyID).
		Build(&secretKey.PublicKey)

	keyPair := jwk.NewKeyBuilder(jwa.ES256).
		WithKeyID(keyID).
		BuildPair(secretKey)

	bytes, err := jwk.WriteSet(jwk.Singleton(sharedKey))
	require.NoError(t, err)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(bytes)
	})
	s := httptest.NewServer(h)
	defer s.Close()

	cfg := &bouncer.Config{
		TokenIssuers:            []string{"https://issuer.com"},
		TokenAudiences:          []string{"my-api"},
		TokenAuthScheme:         "Bearer",
		TokenRolesClaim:         "roles",
		KeysURL:                 s.URL,
		KeysUserAgent:           "Vouch-Test",
		KeysTimeout:             1 * time.Second,
		KeysMinRefreshInterval:  1 * time.Minute,
		KeysMaxRefreshInterval:  1 * time.Hour,
		KeysAttemptLimit:        3,
		KeysBackoffMinDelay:     10 * time.Millisecond,
		KeysBackoffMaxDelay:     50 * time.Millisecond,
		KeysBackoffGrowthFactor: 2.0,
		KeysBackoffJitterAmount: 0.1,
		Logger:                  slog.Default(),
	}

	b := bouncer.New(cfg)

	createToken := func(claims any) string {
		token, err := jwt.Sign(keyPair, claims)
		require.NoError(t, err)
		return string(token)
	}

	validPayload := map[string]any{
		"sub": "warmup",
		"iss": "https://issuer.com",
		"aud": "my-api",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	validToken := createToken(validPayload)

	require.Eventually(t, func() bool {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		_, err := b.Bounce(req)
		return err == nil
	},
		2*time.Second,
		50*time.Millisecond,
		"Bouncer failed to load keys from mock server",
	)

	t.Run("Success", func(t *testing.T) {
		payload := map[string]any{
			"sub":   "alice",
			"iss":   "https://issuer.com",
			"aud":   "my-api",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"roles": []string{"admin", "editor"},
		}
		token := createToken(payload)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		user, err := b.Bounce(req)
		require.NoError(t, err)
		assert.Equal(t, "alice", user.Name)
		assert.Equal(t, []string{"admin", "editor"}, user.Roles)
		assert.Empty(t, req.Header.Get("Authorization"))
	})

	t.Run("Missing Token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		_, err := b.Bounce(req)
		assert.ErrorIs(t, err, bouncer.ErrMissingToken)
	})

	t.Run("Invalid Scheme", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Basic xyz")
		_, err := b.Bounce(req)
		assert.ErrorIs(t, err, bouncer.ErrMissingToken)
	})

	t.Run("Invalid Signature", func(t *testing.T) {
		otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		otherPair := jwk.NewKeyBuilder(jwa.ES256).WithKeyID("other").BuildPair(otherKey)

		payload := map[string]any{"sub": "hacker"}
		token, _ := jwt.Sign(otherPair, payload)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+string(token))

		_, err := b.Bounce(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid access token")
	})

	t.Run("Expired Token", func(t *testing.T) {
		payload := map[string]any{
			"sub": "bob",
			"iss": "https://issuer.com",
			"aud": "my-api",
			"exp": time.Now().Add(-time.Hour).Unix(),
		}
		token := createToken(payload)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := b.Bounce(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token is expired")
	})

	t.Run("Wrong Issuer", func(t *testing.T) {
		payload := map[string]any{
			"sub": "charlie",
			"iss": "https://evil.com",
			"aud": "my-api",
		}
		token := createToken(payload)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := b.Bounce(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid issuer")
	})

	t.Run("MissingUsername", func(t *testing.T) {
		payload := map[string]any{
			"iss": "https://issuer.com",
			"aud": "my-api",
		}
		token := createToken(payload)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := b.Bounce(req)
		assert.ErrorIs(t, err, bouncer.ErrUndefinedUserName)
	})

	t.Run("RolesNotArray", func(t *testing.T) {
		payload := map[string]any{"sub": "dave", "roles": "admin"}
		token := createToken(payload)
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		user, err := b.Bounce(req)
		require.NoError(t, err)
		assert.Empty(t, user.Roles)
	})
}
