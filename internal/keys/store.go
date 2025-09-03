package keys

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

func newRemote(cfg config.Remote) (Store, error) {
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
	ctx := context.Background()
	cache, err := jwk.NewCache(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("create cache: %w", err)
	}
	url := cfg.Endpoint
	min := time.Duration(cfg.Interval) * time.Minute
	max := 2 * min
	err = cache.Register(
		ctx, url,
		jwk.WithMinInterval(min),
		jwk.WithMaxInterval(max),
	)
	if err != nil {
		return nil, fmt.Errorf("register url: %w", err)
	}
	return &remote{cache, url}, nil
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
				if agg.AddKey(key) != nil {
					return nil, err
				}
			}
		}

	}
	return agg, nil
}

func NewStore(cfg config.Keys) (Store, error) {
	var static, remote Store
	if cfg.Static != "" {
		s, err := newStatic(cfg.Static)
		if err != nil {
			return nil, fmt.Errorf("static keys: %w", err)
		}
		static = s
	}
	if cfg.Remote.Endpoint != "" {
		s, err := newRemote(cfg.Remote)
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
