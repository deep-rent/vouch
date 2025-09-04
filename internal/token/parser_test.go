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
		{name: "wrong-scheme", auth: "Basic abc", want: ""},
		{name: "no-token", auth: "Bearer", want: ""},
		{name: "only-spaces-after", auth: "Bearer    ", want: ""},
		{name: "valid", auth: "Bearer token", want: "token"},
		{name: "case-insensitive", auth: "bearer token", want: "token"},
		{name: "leading-trailing-spaces", auth: "  Bearer token  ", want: "token"},
		{name: "multiple-spaces", auth: "BEARER    token", want: "token"},
		{name: "token-with-spaces", auth: "Bearer   tok en   ", want: "tok en"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := bearer(tc.auth); got != tc.want {
				t.Fatalf("bearer(%q) = %q, want %q", tc.auth, got, tc.want)
			}
		})
	}
}

func TestParse_MissingHeader(t *testing.T) {
	t.Parallel()
	p := &Parser{keys: key.ProviderFunc(func(context.Context) (jwk.Set, error) {
		return jwk.NewSet(), nil
	})}
	req := httptest.NewRequest("GET", "/", nil)

	_, err := p.Parse(req)
	if err != ErrMissingToken {
		t.Fatalf("got err = %v, want ErrMissingToken", err)
	}
}

func TestParse_EmptyAfterBearer(t *testing.T) {
	t.Parallel()
	p := &Parser{keys: key.ProviderFunc(func(context.Context) (jwk.Set, error) {
		return jwk.NewSet(), nil
	})}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer  ")

	_, err := p.Parse(req)
	if err != ErrMissingToken {
		t.Fatalf("got err = %v, want ErrMissingToken", err)
	}
}

func TestParse_PropagatesErrors(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("sentinel")
	p := &Parser{keys: key.ProviderFunc(func(context.Context) (jwk.Set, error) {
		return nil, sentinel
	})}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer token")

	_, err := p.Parse(req)
	if err != sentinel {
		t.Fatalf("got err = %v, want %v", err, sentinel)
	}
}

func TestParse_RaisesCorrectErrors(t *testing.T) {
	t.Parallel()
	p := &Parser{keys: key.ProviderFunc(func(ctx context.Context) (jwk.Set, error) {
		return jwk.NewSet(), nil
	})}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid")

	_, err := p.Parse(req)
	if err != ErrInvalidToken {
		t.Fatalf("got err = %v, want ErrInvalidToken", err)
	}
}

func TestParse_PassesRequestContextToProvider(t *testing.T) {
	t.Parallel()
	type pointer struct{}
	const marker = "seen"
	seen := false

	p := &Parser{keys: key.ProviderFunc(func(ctx context.Context) (jwk.Set, error) {
		if v, _ := ctx.Value(pointer{}).(string); v == marker {
			seen = true
		}
		return jwk.NewSet(), nil
	})}

	base := httptest.NewRequest("GET", "/", nil)
	req := base.WithContext(context.WithValue(base.Context(), pointer{}, marker))
	req.Header.Set("Authorization", "Bearer invalid")

	_, _ = p.Parse(req)
	if !seen {
		t.Fatal("provider did not receive the request context")
	}
}
