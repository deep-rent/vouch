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

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/testutil/build"
	"github.com/deep-rent/nexus/testutil/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCompile(t *testing.T) {
	exe := build.Binary(t, ".", "vouch")
	assert.FileExists(t, exe)
}

func TestVersion(t *testing.T) {
	var buf bytes.Buffer
	err := boot(context.Background(), []string{"vouch", "-v"}, &buf)
	require.NoError(t, err)
	assert.Contains(t, buf.String(), "dev", "output should contain the version")
}

func TestMissingConfig(t *testing.T) {
	key := "VOUCH_KEYS_URL"
	if val, ok := os.LookupEnv(key); ok {
		defer func() {
			_ = os.Setenv(key, val)
		}()
	}
	require.NoError(t, os.Unsetenv(key))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := boot(ctx, []string{"vouch"}, io.Discard)
	assert.Error(t, err)
	if err != nil {
		assert.Contains(
			t,
			err.Error(),
			"required variable \"VOUCH_KEYS_URL\" is not set",
		)
	}
}

func TestIntegration(t *testing.T) {
	mat, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pub := &mat.PublicKey
	keyID := "test"
	key := jwk.NewKeyBuilder(jwa.RS256).WithKeyID(keyID).Build(pub)
	set := jwk.Singleton(key)

	h1 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, err := jwk.WriteSet(set)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	})

	jwks := httptest.NewServer(h1)
	defer jwks.Close()

	h2 := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get("X-Auth-CouchDB-UserName")
		roles := r.Header.Get("X-Auth-CouchDB-Roles")

		if user == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("missing user header"))
			return
		}

		w.Header().Set("X-Received-User", user)
		w.Header().Set("X-Received-Roles", roles)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	target := httptest.NewServer(h2)
	defer target.Close()

	port := ports.FreeT(t)
	host := "127.0.0.1"
	baseURL := fmt.Sprintf("http://%s:%d", host, port)

	t.Setenv("VOUCH_KEYS_URL", jwks.URL)
	t.Setenv("VOUCH_TARGET", target.URL)
	t.Setenv("VOUCH_PORT", fmt.Sprintf("%d", port))
	t.Setenv("VOUCH_HOST", host)
	t.Setenv("VOUCH_LOG_LEVEL", "debug")
	t.Setenv("VOUCH_KEYS_MIN_REFRESH_INTERVAL", "1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = boot(ctx, []string{"vouch"}, io.Discard)
	}()

	ports.WaitT(t, host, port)

	signer := jwt.NewSigner(
		jwk.NewKeyBuilder(jwa.RS256).
			WithKeyID(keyID).
			BuildPair(mat),
	)

	type Claims struct {
		jwt.Reserved
		Roles []string `json:"_couchdb.roles"`
	}

	payload := &Claims{
		Reserved: jwt.Reserved{Sub: "alice"},
		Roles:    []string{"admin", "basic"},
	}
	token, err := signer.Sign(payload)
	require.NoError(t, err)

	client := &http.Client{Timeout: 5 * time.Second}
	var res *http.Response

	require.Eventually(t, func() bool {
		req, _ := http.NewRequest("GET", baseURL+"/some/db", nil)
		req.Header.Set("Authorization", "Bearer "+string(token))

		res, err = client.Do(req)
		if err != nil {
			return false
		}
		defer func() {
			_ = res.Body.Close()
		}()
		return res.StatusCode == http.StatusOK
	},
		5*time.Second,
		200*time.Millisecond,
		"Vouch failed to proxy valid request",
	)

	assert.Equal(t, "alice", res.Header.Get("X-Received-User"))
	assert.Equal(t, "admin,basic", res.Header.Get("X-Received-Roles"))

	badReq, _ := http.NewRequest("GET", baseURL+"/some/db", nil)
	badReq.Header.Set("Authorization", "Bearer invalid.token.here")
	badRes, err := client.Do(badReq)
	require.NoError(t, err)
	defer func() {
		_ = badRes.Body.Close()
	}()

	assert.Equal(t, http.StatusUnauthorized, badRes.StatusCode)
}
