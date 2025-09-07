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

package token

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/vouch/internal/key"
	"github.com/lestrrat-go/jwx/v3/jwk"
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
		{name: "leading trailing spaces", auth: "  Bearer token  ", want: "token"},
		{name: "multiple spaces", auth: "BEARER    token", want: "token"},
		{name: "token with spaces", auth: "Bearer   tok en   ", want: "tok en"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := bearer(tc.auth)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestParseMissingHeader(t *testing.T) {
	t.Parallel()
	p := &parser{keys: key.ProviderFunc(func(context.Context) (jwk.Set, error) {
		return jwk.NewSet(), nil
	})}
	req := httptest.NewRequest("GET", "/", nil)

	_, err := p.Parse(req)
	require.ErrorIs(t, err, ErrMissingToken)
}

func TestParseEmptyAfterBearer(t *testing.T) {
	t.Parallel()
	p := &parser{keys: key.ProviderFunc(func(context.Context) (jwk.Set, error) {
		return jwk.NewSet(), nil
	})}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(Header, "Bearer  ")

	_, err := p.Parse(req)
	require.ErrorIs(t, err, ErrMissingToken)
}

func TestParsePropagatesErrors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("sentinel")
	p := &parser{keys: key.ProviderFunc(func(context.Context) (jwk.Set, error) {
		return nil, sentinel
	})}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(Header, "Bearer token")

	_, err := p.Parse(req)
	require.ErrorIs(t, err, sentinel)
}

func TestParseRaisesCorrectErrors(t *testing.T) {
	t.Parallel()
	p := &parser{keys: key.ProviderFunc(func(ctx context.Context) (jwk.Set, error) {
		return jwk.NewSet(), nil
	})}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set(Header, "Bearer invalid")

	_, err := p.Parse(req)
	require.ErrorIs(t, err, ErrInvalidToken)
}

func TestParsePassesRequestContextToProvider(t *testing.T) {
	t.Parallel()
	type markerKey struct{}
	const marker = "seen"
	seen := false

	p := &parser{keys: key.ProviderFunc(func(ctx context.Context) (jwk.Set, error) {
		if v, _ := ctx.Value(markerKey{}).(string); v == marker {
			seen = true
		}
		return jwk.NewSet(), nil
	})}

	base := httptest.NewRequest("GET", "/", nil)
	req := base.WithContext(context.WithValue(base.Context(), markerKey{}, marker))
	req.Header.Set(Header, "Bearer invalid")

	_, _ = p.Parse(req)
	assert.True(t, seen, "provider did not receive the request context")
}
