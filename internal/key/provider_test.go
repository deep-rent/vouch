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

package key

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func createJWKS(kid string) []byte {
	k := base64.RawURLEncoding.EncodeToString([]byte("secret"))
	s := `{"kty":"oct","kid":"` + kid + `","k":"` + k + `"}`
	return []byte(`{"keys":[` + s + `]}`)
}

func createFile(t *testing.T, kid string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, createJWKS(kid), 0o600); err != nil {
		t.Fatalf("write jwks: %v", err)
	}
	return path
}

func serveJWKS(t *testing.T, kid string) (url string, stop func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(createJWKS(kid))
	}))
	return srv.URL, srv.Close
}

func assertHas(t *testing.T, set jwk.Set, kids ...string) {
	t.Helper()

	exp := make(map[string]struct{}, set.Len())
	for i := 0; i < set.Len(); i++ {
		k, ok := set.Key(i)
		if !ok {
			t.Fatalf("key index %d out of range", i)
		}
		var kid string
		_ = k.Get(jwk.KeyIDKey, &kid)
		if kid != "" {
			exp[kid] = struct{}{}
		}
	}

	for _, kid := range kids {
		if _, ok := exp[kid]; !ok {
			t.Fatalf("expected kid %q in set, have %v", kid, exp)
		}
	}
}

func TestStaticProvider_Success(t *testing.T) {
	kid := "static"
	file := createFile(t, kid)

	p, err := newStatic(file)
	if err != nil {
		t.Fatalf("create static: %v", err)
	}

	set, err := p.Keys(context.Background())
	if err != nil {
		t.Fatalf("get keys: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("got %d keys, want 1", set.Len())
	}
	assertHas(t, set, kid)
}

func TestStaticProvider_MissingFile(t *testing.T) {
	if _, err := newStatic("missing.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestStaticProvider_NonRegularFile(t *testing.T) {
	if _, err := newStatic(t.TempDir()); err == nil {
		t.Fatal("expected error for non-regular file")
	}
}

func TestStaticProvider_InvalidJSON(t *testing.T) {
	file := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(file, []byte("{invalid}"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := newStatic(file); err == nil {
		t.Fatal("expected error for invalid jwks json")
	}
}

func TestRemoteProvider_Success(t *testing.T) {
	kid := "remote"
	url, stop := serveJWKS(t, kid)
	t.Cleanup(stop)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	p, err := newRemote(ctx, config.Remote{
		Endpoint: url,
		Interval: 500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create remote: %v", err)
	}

	set, err := p.Keys(ctx)
	if err != nil {
		t.Fatalf("get keys: %v", err)
	}
	if set.Len() != 1 {
		t.Fatalf("got %d keys, want 1", set.Len())
	}
	assertHas(t, set, kid)
}

func TestCompositeProvider_MergesSets(t *testing.T) {
	prv := func(kid string) Provider {
		set, err := jwk.Parse(createJWKS(kid))
		if err != nil {
			t.Fatalf("parse jwks: %v", err)
		}
		return ProviderFunc(func(context.Context) (jwk.Set, error) {
			return set, nil
		})
	}
	c := &composite{stores: []Provider{
		prv("k1"),
		prv("k2"),
	}}
	set, err := c.Keys(context.Background())
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	assertHas(t, set, "k1", "k2")
}

func TestCompositeProvider_PropagatesError(t *testing.T) {
	oops := errors.New("oops")
	jwks, err := jwk.Parse(createJWKS("ok"))
	if err != nil {
		t.Fatalf("parse jwks: %v", err)
	}
	c := &composite{stores: []Provider{
		ProviderFunc(func(context.Context) (jwk.Set, error) { return jwks, nil }),
		ProviderFunc(func(context.Context) (jwk.Set, error) { return nil, oops }),
	}}
	if _, err := c.Keys(context.Background()); err == nil {
		t.Fatal("expected error from composite.Keys")
	}
}

func TestNewProvider_NoneConfigured(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	p, err := NewProvider(ctx, config.Keys{})
	if err != nil {
		t.Fatalf("create provider: %v", err)
	}
	if p != nil {
		t.Fatalf("expected nil provider when neither static nor remote set")
	}
}

func TestNewProvider_StaticOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	path := createFile(t, "static")
	p, err := NewProvider(ctx, config.Keys{Static: path})
	if err != nil {
		t.Fatalf("create provider (static): %v", err)
	}
	set, err := p.Keys(ctx)
	if err != nil {
		t.Fatalf("get keys (static): %v", err)
	}
	assertHas(t, set, "static")
}

func TestNewProvider_RemoteOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	url, stop := serveJWKS(t, "remote")
	t.Cleanup(stop)

	p, err := NewProvider(ctx, config.Keys{
		Remote: config.Remote{
			Endpoint: url,
			Interval: 500 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("create provider (remote): %v", err)
	}
	set, err := p.Keys(ctx)
	if err != nil {
		t.Fatalf("get keys (remote): %v", err)
	}
	assertHas(t, set, "remote")
}

func TestNewProvider_Composite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)

	url, stop := serveJWKS(t, "remote")
	t.Cleanup(stop)

	p, err := NewProvider(ctx, config.Keys{
		Static: createFile(t, "static"),
		Remote: config.Remote{
			Endpoint: url,
			Interval: 500 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatalf("create provider (composite): %v", err)
	}
	set, err := p.Keys(ctx)
	if err != nil {
		t.Fatalf("get keys (composite): %v", err)
	}
	assertHas(t, set, "static", "remote")
}
