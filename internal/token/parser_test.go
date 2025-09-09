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

package token_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/key"
	"github.com/deep-rent/vouch/internal/token"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBearer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		auth string
		want string
	}{
		{name: "empty", auth: "", want: ""},
		{name: "spaces", auth: "   ", want: ""},
		{name: "wrong scheme", auth: "Basic abc", want: ""},
		{name: "no token", auth: "Bearer", want: ""},
		{name: "only spaces after", auth: "Bearer    ", want: ""},
		{name: "valid", auth: "Bearer token", want: "token"},
		{name: "case-insensitive", auth: "bearer token", want: "token"},
		{
			name: "leading trailing spaces",
			auth: "  Bearer token  ",
			want: "token",
		},
		{name: "multiple spaces", auth: "BEARER    token", want: "token"},
		{name: "token with spaces", auth: "Bearer   tok en   ", want: "tok en"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := token.Bearer(tc.auth)
			assert.Equal(t, tc.want, got)
		})
	}
}

func mockParser(set jwk.Set, err error) token.Parser {
	return token.NewParserWithKeys(
		key.ProviderFunc(func(context.Context) (jwk.Set, error) {
			return set, err
		}),
	)
}

func TestParseMissingHeader(t *testing.T) {
	t.Parallel()
	p := mockParser(jwk.NewSet(), nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := p.Parse(req)
	require.ErrorIs(t, err, token.ErrMissingToken)
}

func TestParseEmptyAfterBearer(t *testing.T) {
	t.Parallel()
	p := mockParser(jwk.NewSet(), nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(token.Header, "Bearer  ")

	_, err := p.Parse(req)
	require.ErrorIs(t, err, token.ErrMissingToken)
}

func TestParsePropagatesErrors(t *testing.T) {
	t.Parallel()
	p := mockParser(nil, assert.AnError)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(token.Header, "Bearer token")

	_, err := p.Parse(req)
	require.ErrorIs(t, err, assert.AnError)
}

func TestParseRaisesCorrectErrors(t *testing.T) {
	t.Parallel()
	p := mockParser(jwk.NewSet(), nil)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(token.Header, "Bearer invalid")

	_, err := p.Parse(req)
	require.ErrorIs(t, err, token.ErrInvalidToken)
}

func TestNewParser(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		const jwks = `{"keys":[{"kty":"oct","k":"c2VjcmV0","alg":"HS256","kid":"k1"}]}`
		path := filepath.Join(t.TempDir(), "keys.jwks")
		require.NoError(t, os.WriteFile(path, []byte(jwks), 0o600))

		cfg := config.Token{
			Keys:     config.Keys{Static: path},
			Issuer:   "iss",
			Audience: "aud",
			Leeway:   1 * time.Second,
			Clock: jwt.ClockFunc(
				func() time.Time { return time.UnixMilli(1) },
			),
		}

		p, err := token.NewParser(t.Context(), cfg)
		require.NoError(t, err)
		require.NotNil(t, p)
	})

	t.Run("error invalid static path", func(t *testing.T) {
		cfg := config.Token{
			Keys: config.Keys{
				Static: filepath.Join(t.TempDir(), "missing.jwks"),
			},
		}
		p, err := token.NewParser(t.Context(), cfg)
		require.Error(t, err)
		assert.Nil(t, p)
		assert.Contains(t, err.Error(), "create key provider")
	})
}
