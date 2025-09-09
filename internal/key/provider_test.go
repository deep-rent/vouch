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

package key_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/key"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	jwksStatic = `{
    "keys": [{
      "kty": "oct",
      "kid": "static-key-1",
      "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    }]
  }`
	jwksRemote = `{
    "keys": [{
      "kty": "oct",
      "kid": "remote-key-1",
      "k": "GcE_p-Jc3gY5f7tXMLt0bn_m2w_e2Z2a53S-4_s-GjA"
    }]
  }`
)

// writeJWKS creates a temporary file containing the given JWKS and returns
// the absolute file path.
func writeJWKS(t *testing.T, data string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "test-*.jwks")
	require.NoError(t, err)
	_, err = f.WriteString(data)
	require.NoError(t, err)
	require.NoError(t, f.Close())
	return f.Name()
}

// serveJWKS starts a test HTTP server that serves the given JWKS under the
// base URL. The caller is responsible for closing the server.
func serveJWKS(_ *testing.T, data string) *httptest.Server {
	h := http.HandlerFunc(func(res http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(res, data)
	})
	return httptest.NewServer(h)
}

func TestNewStatic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		path := writeJWKS(t, jwksStatic)
		p, err := key.NewStaticProvider(path)
		require.NoError(t, err)
		require.NotNil(t, p)

		keys, err := p.Keys(t.Context())
		require.NoError(t, err)
		assert.Equal(t, 1, keys.Len())
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := key.NewStaticProvider("missing.jwks")
		require.Error(t, err)
		assert.ErrorContains(t, err, "stat file")
	})

	t.Run("path is directory", func(t *testing.T) {
		_, err := key.NewStaticProvider(t.TempDir())
		require.Error(t, err)
		assert.ErrorContains(t, err, "is not regular")
	})

	t.Run("invalid jwks data", func(t *testing.T) {
		path := writeJWKS(t, `{"keys": "invalid"}`)
		_, err := key.NewStaticProvider(path)
		require.Error(t, err)
		assert.ErrorContains(t, err, "parse jwk")
	})
}

func TestNewRemote(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctx := t.Context()
		srv := serveJWKS(t, jwksRemote)
		defer srv.Close()

		cfg := config.Remote{
			Endpoint: srv.URL,
			Interval: 1 * time.Second,
		}
		p, err := key.NewRemoteProvider(ctx, cfg)
		require.NoError(t, err)
		require.NotNil(t, p)

		keys, err := p.Keys(ctx)
		require.NoError(t, err)
		assert.Equal(t, 1, keys.Len())
	})

	t.Run("server error", func(t *testing.T) {
		ctx := t.Context()
		srv := httptest.NewServer(http.HandlerFunc(func(
			res http.ResponseWriter, _ *http.Request,
		) {
			res.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		cfg := config.Remote{
			Endpoint: srv.URL,
			Interval: 1 * time.Second,
		}
		_, err := key.NewRemoteProvider(ctx, cfg)
		require.Error(t, err)
		assert.ErrorContains(t, err, "register url")
	})
}

func TestNewProvider(t *testing.T) {
	src := writeJWKS(t, jwksStatic)
	srv := serveJWKS(t, jwksRemote)
	defer srv.Close()

	tests := []struct {
		name     string
		cfg      config.Keys
		wantImpl any
		wantLen  int
		wantFail bool
		wantErr  string
	}{
		{
			name: "static only",
			cfg: config.Keys{
				Static: src,
			},
			wantImpl: &key.StaticProvider{},
			wantLen:  1,
		},
		{
			name: "remote only",
			cfg: config.Keys{
				Remote: config.Remote{
					Endpoint: srv.URL,
					Interval: 1 * time.Second,
				},
			},
			wantImpl: &key.RemoteProvider{},
			wantLen:  1,
		},
		{
			name: "static and remote",
			cfg: config.Keys{
				Static: src,
				Remote: config.Remote{
					Endpoint: srv.URL,
					Interval: 1 * time.Second,
				},
			},
			wantImpl: &key.CompositeProvider{},
			wantLen:  2,
		},
		{
			name:     "no provider configured",
			cfg:      config.Keys{},
			wantFail: true,
			wantErr:  "no key source provided",
		},
		{
			name: "static provider fails",
			cfg: config.Keys{
				Static: filepath.Join(t.TempDir(), "missing.jwks"),
			},
			wantFail: true,
			wantErr:  "static keys",
		},
		{
			name: "remote provider fails (initial fetch)",
			cfg: config.Keys{
				Remote: config.Remote{
					Endpoint: "http://127.0.0.1:9",
					Interval: 1 * time.Second,
				},
			},
			wantFail: true,
			wantErr:  "remote keys",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			p, err := key.NewProvider(ctx, tc.cfg)

			if tc.wantFail {
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			require.IsType(t, tc.wantImpl, p)

			keys, err := p.Keys(ctx)
			require.NoError(t, err)
			assert.Equal(t, tc.wantLen, keys.Len())
		})
	}
}

func TestProviderFunc(t *testing.T) {
	set := jwk.NewSet()
	p := key.ProviderFunc(func(context.Context) (jwk.Set, error) {
		return set, nil
	})
	got, err := p.Keys(t.Context())
	require.NoError(t, err)
	require.Equal(t, set, got)
}

func TestCompositeProviderError(t *testing.T) {
	p := key.ProviderFunc(func(context.Context) (jwk.Set, error) {
		return nil, assert.AnError
	})
	q := key.Compose(p)
	_, err := q.Keys(t.Context())

	require.ErrorIs(t, err, assert.AnError)
}
