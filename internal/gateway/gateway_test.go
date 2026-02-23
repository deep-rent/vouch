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

package gateway_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/deep-rent/vouch/internal/gateway"
	"github.com/deep-rent/vouch/internal/stamper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGateway_ServeHTTP(t *testing.T) {
	// Ensure the test client bypasses any local proxy settings.
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")

	// Setup a mock backend
	called := false
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Verify stamped headers
		assert.Equal(t, "alice", r.Header.Get("X-Vouch-User"))
		assert.Equal(t, "admin", r.Header.Get("X-Vouch-Roles"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("backend response"))
	})

	backend := httptest.NewServer(h)
	defer backend.Close()

	backendURL, err := url.Parse(backend.URL)
	require.NoError(t, err)

	// Host a mock JWKS
	secretKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	keyID := "test"

	sharedKey := jwk.NewKeyBuilder(jwa.ES256).
		WithKeyID(keyID).
		Build(&secretKey.PublicKey)

	keyPair := jwk.NewKeyBuilder(jwa.ES256).
		WithKeyID(keyID).
		BuildPair(secretKey)

	jwks, err := jwk.WriteSet(jwk.Singleton(sharedKey))
	require.NoError(t, err)

	authServer := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwks)
		}),
	)
	defer authServer.Close()

	// Initialize the bouncer
	bouncerCfg := &bouncer.Config{
		TokenIssuers:            []string{"https://issuer.com"},
		TokenAudiences:          []string{"app"},
		TokenAuthScheme:         "Bearer",
		TokenRolesClaim:         "roles",
		KeysURL:                 authServer.URL,
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
	b := bouncer.New(bouncerCfg)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		_ = b.Start(ctx)
	}()

	// Initialize the stamper
	stamperCfg := &stamper.Config{
		UserNameHeader: "X-Vouch-User",
		RolesHeader:    "X-Vouch-Roles",
	}
	s := stamper.New(stamperCfg)

	// Construct the gateway
	gwCfg := &gateway.Config{
		Bouncer:         b,
		Stamper:         s,
		URL:             backendURL,
		FlushInterval:   100 * time.Millisecond,
		MinBufferSize:   1024,
		MaxBufferSize:   2048,
		MaxIdleConns:    10,
		IdleConnTimeout: 90 * time.Second,
		Logger:          slog.Default(),
	}
	gw := gateway.New(gwCfg)

	// Helper to create tokens
	createToken := func(claims any) string {
		token, err := jwt.Sign(keyPair, claims)
		require.NoError(t, err)
		return string(token)
	}

	// Wait for bouncer to load keys
	validToken := createToken(map[string]any{
		"sub": "warmup",
		"iss": "https://issuer.com",
		"aud": "app",
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	require.Eventually(t, func() bool {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		_, err := b.Bounce(req)
		return err == nil
	},
		2*time.Second,
		50*time.Millisecond,
		"Bouncer failed to load keys",
	)

	t.Run("Authorized", func(t *testing.T) {
		called = false
		payload := map[string]any{
			"sub":   "alice",
			"iss":   "https://issuer.com",
			"aud":   "app",
			"exp":   time.Now().Add(time.Hour).Unix(),
			"roles": []string{"admin"},
		}
		token := createToken(payload)

		req := httptest.NewRequest("GET", "/resource", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()

		gw.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "backend response", rec.Body.String())
		assert.True(t, called, "Backend should have been called")
	})

	t.Run("Unauthorized_MissingToken", func(t *testing.T) {
		called = false
		req := httptest.NewRequest("GET", "/resource", nil)
		rec := httptest.NewRecorder()

		gw.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, called, "Backend should NOT have been called")
	})

	t.Run("Unauthorized_InvalidToken", func(t *testing.T) {
		called = false
		req := httptest.NewRequest("GET", "/resource", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		rec := httptest.NewRecorder()

		gw.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, called, "Backend should NOT have been called")
	})
}
