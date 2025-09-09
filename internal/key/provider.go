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
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// Provider supplies a JSON Web Key Set (JWKS) used to verify signatures of
// incoming access tokens. Implementations may load keys from disk, fetch them
// remotely, or aggregate multiple sources.
type Provider interface {
	// Keys returns the current JWK set. It may fetch or refresh keys as needed.
	Keys(ctx context.Context) (jwk.Set, error)
}

// ProviderFunc is a small adapter for functional implementations of Provider.
type ProviderFunc func(ctx context.Context) (jwk.Set, error)

// Keys implements the Provider interface.
func (f ProviderFunc) Keys(ctx context.Context) (jwk.Set, error) {
	return f(ctx)
}

// StaticProvider implements Provider by serving keys from a static
// JWKS document loaded from the local filesystem at startup.
type StaticProvider struct {
	set jwk.Set
}

// Keys returns the pre-parsed static JWK set.
func (s *StaticProvider) Keys(context.Context) (jwk.Set, error) {
	return s.set, nil
}

// Ensure static satisfies the Provider contract.
var _ Provider = (*StaticProvider)(nil)

// NewStaticProvider constructs a static key Provider from a JWKS file at path.
// The file must exist and be a regular file. The JWKS is parsed eagerly.
func NewStaticProvider(path string) (Provider, error) {
	if f, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("stat file %q: %w", path, err)
	} else if !f.Mode().IsRegular() {
		return nil, fmt.Errorf("file %q exists but is not regular", path)
	}
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file %q: %w", path, err)
	}
	set, err := jwk.Parse(buf)
	if err != nil {
		return nil, fmt.Errorf("parse jwk: %w", err)
	}
	return &StaticProvider{set}, nil
}

// RemoteProvider implements Provider by retrieving keys from a remote
// JWKS endpoint. It relies on jwk.Cache to handle background refreshes and
// rate limiting.
type RemoteProvider struct {
	cache *jwk.Cache
	url   string
}

// Keys looks up (and possibly refreshes) the JWK set for the configured URL.
func (r *RemoteProvider) Keys(ctx context.Context) (jwk.Set, error) {
	return r.cache.Lookup(ctx, r.url)
}

// Ensure remote satisfies the Provider contract.
var _ Provider = (*RemoteProvider)(nil)

// userAgentTransport is an http.RoundTripper that sets a custom User-Agent
// header on all requests before delegating to an underlying transport.
type userAgentTransport struct {
	UserAgent string
	Transport http.RoundTripper
}

// RoundTrip implements the http.RoundTripper interface.
func (t *userAgentTransport) RoundTrip(
	req *http.Request,
) (*http.Response, error) {
	req.Header.Set("User-Agent", t.UserAgent)
	return t.Transport.RoundTrip(req)
}

// Ensure userAgentTransport satisfies the http.RoundTripper contract.
var _ http.RoundTripper = (*userAgentTransport)(nil)

// newClient constructs an HTTP client for remote key fetching with sensible
// defaults and a custom User-Agent header.
func newClient(cfg config.Remote) *httprc.Client {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &userAgentTransport{
			UserAgent: cfg.UserAgent,
			Transport: http.DefaultTransport,
		},
	}
	return httprc.NewClient(
		httprc.WithHTTPClient(client),
	)
}

// NewRemoteProvider constructs a remote key Provider backed by jwk.Cache and
// a tuned HTTP client. The cache is registered to poll cfg.Endpoint at
// cfg.Interval. It uses a short timeout for the initial registration fetch
// so that permanently failing endpoints do not block startup indefinitely.
func NewRemoteProvider(
	ctx context.Context,
	cfg config.Remote,
) (Provider, error) {
	cache, err := jwk.NewCache(ctx, newClient(cfg))
	if err != nil {
		return nil, fmt.Errorf("create cache: %w", err)
	}
	wait, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	if err := cache.Register(
		wait,
		cfg.Endpoint,
		jwk.WithMinInterval(cfg.Interval),
	); err != nil {
		return nil, fmt.Errorf("register url: %w", err)
	}

	return &RemoteProvider{cache, cfg.Endpoint}, nil
}

// CompositeProvider implements Provider by aggregating keys from
// multiple Providers. Keys from all sources are merged into a single jwk.Set.
type CompositeProvider struct {
	prvs []Provider
}

// Keys merges the sets from all underlying Providers into a new set.
// If multiple providers expose the same key, AddKey may de-duplicate based
// on key ID and material as implemented by the jwk library.
func (c *CompositeProvider) Keys(ctx context.Context) (jwk.Set, error) {
	agg := jwk.NewSet()
	for _, store := range c.prvs {
		set, err := store.Keys(ctx)
		if err != nil {
			return nil, err
		}
		for i := range set.Len() {
			if key, ok := set.Key(i); ok {
				if err := agg.AddKey(key); err != nil {
					return nil, fmt.Errorf("add key: %w", err)
				}
			}
		}
	}
	return agg, nil
}

// Compose constructs a composite Provider from multiple
// Providers that will be queried in order.
func Compose(prvs ...Provider) Provider {
	return &CompositeProvider{
		prvs: prvs,
	}
}

// Ensure composite satisfies the Provider contract.
var _ Provider = (*CompositeProvider)(nil)

// NewProvider builds a Provider from configuration:
//   - If only static is configured, returns a static provider.
//   - If only remote is configured, returns a remote provider.
//   - If both are configured, returns a composite provider that merges both.
//
// If neither is configured, an error will be returned.
func NewProvider(ctx context.Context, cfg config.Keys) (Provider, error) {
	var prvs []Provider
	if cfg.Static != "" {
		s, err := NewStaticProvider(cfg.Static)
		if err != nil {
			return nil, fmt.Errorf("static keys: %w", err)
		}
		prvs = append(prvs, s)
	}
	if cfg.Remote.Endpoint != "" {
		r, err := NewRemoteProvider(ctx, cfg.Remote)
		if err != nil {
			return nil, fmt.Errorf("remote keys: %w", err)
		}
		prvs = append(prvs, r)
	}
	switch len(prvs) {
	case 0:
		return nil, errors.New("no key source provided")
	case 1:
		return prvs[0], nil
	default:
		return Compose(prvs...), nil
	}
}
