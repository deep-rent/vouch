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
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type Store interface {
	Keys(ctx context.Context) (jwk.Set, error)
}

type static struct {
	set jwk.Set
}

func (s *static) Keys(ctx context.Context) (jwk.Set, error) {
	return s.set, nil
}

func newStatic(path string) (Store, error) {
	if fi, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("stat file %q: %w", path, err)
	} else if !fi.Mode().IsRegular() {
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
	return &static{set}, nil
}

type remote struct {
	cache *jwk.Cache
	url   string
}

func (r *remote) Keys(ctx context.Context) (jwk.Set, error) {
	return r.cache.Lookup(ctx, r.url)
}

func newRemote(ctx context.Context, cfg config.Remote) (Store, error) {
	client := httprc.NewClient(httprc.WithHTTPClient(&http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        32,
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}))
	cache, err := jwk.NewCache(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("create cache: %w", err)
	}
	if err := cache.Register(
		ctx,
		cfg.Endpoint,
		jwk.WithMinInterval(cfg.Interval),
		jwk.WithMaxInterval(cfg.Interval*2),
	); err != nil {
		return nil, fmt.Errorf("register url: %w", err)
	}

	// Pre-warm asynchronously so first request doesn’t pay the fetch cost
	go func() {
		wt, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = cache.Lookup(wt, cfg.Endpoint)
	}()
	return &remote{cache, cfg.Endpoint}, nil
}

type composite struct {
	stores []Store
}

func (c *composite) Keys(ctx context.Context) (jwk.Set, error) {
	agg := jwk.NewSet()
	for _, store := range c.stores {
		set, err := store.Keys(ctx)
		if err != nil {
			return nil, err
		}
		for i := 0; i < set.Len(); i++ {
			if key, ok := set.Key(i); ok {
				if err := agg.AddKey(key); err != nil {
					return nil, fmt.Errorf("add key: %w", err)
				}
			}
		}

	}
	return agg, nil
}

func NewStore(ctx context.Context, cfg config.Keys) (Store, error) {
	var static, remote Store
	if cfg.Static != "" {
		s, err := newStatic(cfg.Static)
		if err != nil {
			return nil, fmt.Errorf("static keys: %w", err)
		}
		static = s
	}
	if cfg.Remote.Endpoint != "" {
		s, err := newRemote(ctx, cfg.Remote)
		if err != nil {
			return nil, fmt.Errorf("remote keys: %w", err)
		}
		remote = s
	}
	if static == nil {
		return remote, nil
	}
	if remote == nil {
		return static, nil
	}
	return &composite{
		stores: []Store{
			static,
			remote,
		},
	}, nil
}
