// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
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

package bouncer_test

import (
	"context"
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
	// Ensure the test client bypasses any local proxy settings.
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

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
		_, _ = w.Write(bytes)
	})
	s := httptest.NewServer(h)
	defer s.Close()

	cfg := &bouncer.Config{
		TokenIssuers:            []string{"https://issuer.com"},
		TokenAudiences:          []string{"consumer"},
		TokenAuthScheme:         "Bearer",
		TokenRolesClaim:         "roles",
		KeysURL:                 s.URL,
		KeysUserAgent:           "Vouch-Test",
		KeysTimeout:             1 * time.Second,
		KeysMinRefreshInterval:  100 * time.Millisecond,
		KeysMaxRefreshInterval:  1 * time.Hour,
		KeysAttemptLimit:        3,
		KeysBackoffMinDelay:     10 * time.Millisecond,
		KeysBackoffMaxDelay:     50 * time.Millisecond,
		KeysBackoffGrowthFactor: 2.0,
		KeysBackoffJitterAmount: 0.1,
		Logger:                  slog.Default(),
	}

	b := bouncer.New(cfg)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go func() {
		_ = b.Start(ctx)
	}()

	createToken := func(claims any) string {
		token, err := jwt.Sign(keyPair, claims)
		require.NoError(t, err)
		return string(token)
	}

	validPayload := map[string]any{
		"sub": "warmup",
		"iss": "https://issuer.com",
		"aud": "consumer",
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
			"aud":   "consumer",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"roles": []string{"admin", "basic"},
		}
		token := createToken(payload)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		user, err := b.Bounce(req)
		require.NoError(t, err)
		assert.Equal(t, "alice", user.Name)
		assert.Equal(t, []string{"admin", "basic"}, user.Roles)
		assert.Empty(t, req.Header.Get("Authorization"))
	})

	t.Run("MissingToken", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		_, err := b.Bounce(req)
		assert.ErrorIs(t, err, bouncer.ErrMissingToken)
	})

	t.Run("InvalidScheme", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Basic xyz")
		_, err := b.Bounce(req)
		assert.ErrorIs(t, err, bouncer.ErrMissingToken)
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.Nil(t, err)

		otherKeyPair := jwk.NewKeyBuilder(jwa.ES256).
			WithKeyID("other").
			BuildPair(otherKey)

		payload := map[string]any{"sub": "hacker"}
		token, err := jwt.Sign(otherKeyPair, payload)
		require.Nil(t, err)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+string(token))

		_, err = b.Bounce(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid access token")
	})

	t.Run("ExpiredToken", func(t *testing.T) {
		payload := map[string]any{
			"sub": "bob",
			"iss": "https://issuer.com",
			"aud": "consumer",
			"exp": time.Now().Add(-time.Hour).Unix(),
		}
		token := createToken(payload)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := b.Bounce(req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "token is expired")
	})

	t.Run("WrongIssuer", func(t *testing.T) {
		payload := map[string]any{
			"sub": "charlie",
			"iss": "https://evil.com",
			"aud": "consumer",
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
			"aud": "consumer",
		}
		token := createToken(payload)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := b.Bounce(req)
		assert.ErrorIs(t, err, bouncer.ErrUndefinedUserName)
	})

	t.Run("RolesNotArray", func(t *testing.T) {
		payload := map[string]any{
			"sub":   "joe",
			"iss":   "https://issuer.com",
			"aud":   "consumer",
			"roles": "admin",
		}
		token := createToken(payload)
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		user, err := b.Bounce(req)

		require.NoError(t, err)
		assert.Empty(t, user.Roles)
	})
}
