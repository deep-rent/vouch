package token

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/deep-rent/vouch/internal/cache"
)

var (
	errImmutable = errors.New("set is read-only")
	errNotLoaded = errors.New("set is not yet loaded")
)

// cachedSet wraps a refreshing cache to provide an immutable,
// nil-safe implementation of the jwk.Set interface.
type cachedSet struct {
	cache *cache.Cache[jwk.Set]
}

func (s *cachedSet) cached() jwk.Set {
	return s.cache.Get()
}

func (s *cachedSet) AddKey(jwk.Key) error {
	return errImmutable
}

func (s *cachedSet) Clear() error {
	return errImmutable
}

func (s *cachedSet) Set(string, any) error {
	return errImmutable
}

func (s *cachedSet) Remove(string) error {
	return errImmutable
}

func (s *cachedSet) RemoveKey(jwk.Key) error {
	return errImmutable
}

func (s *cachedSet) Key(i int) (jwk.Key, bool) {
	set := s.cached()
	if set != nil {
		return set.Key(i)
	}
	return nil, false
}

func (s *cachedSet) Get(k string, v any) error {
	set := s.cached()
	if set != nil {
		return set.Get(k, v)
	}
	return errNotLoaded
}

func (s *cachedSet) Index(key jwk.Key) int {
	set := s.cached()
	if set != nil {
		return set.Index(key)
	}
	return -1
}

func (s *cachedSet) Len() int {
	set := s.cached()
	if set != nil {
		return set.Len()
	}
	return 0
}

func (s *cachedSet) LookupKeyID(id string) (jwk.Key, bool) {
	set := s.cached()
	if set != nil {
		return set.LookupKeyID(id)
	}
	return nil, false
}

func (s *cachedSet) Keys() []string {
	set := s.cached()
	if set != nil {
		return set.Keys()
	}
	return []string{}
}

func (s *cachedSet) Clone() (jwk.Set, error) {
	set := s.cached()
	if set != nil {
		return set.Clone()
	}
	return nil, errNotLoaded
}

// Asserts at compile time that *cacheSet satisfies the jwk.Set interface.
var _ jwk.Set = (*cachedSet)(nil)

// mapper transforms the response body into a jwk.Set.
var mapper cache.Mapper[jwk.Set] = func(body []byte) (jwk.Set, error) {
	return jwk.Parse(body)
}

// NewKeySet creates a new auto-refreshing, immutable jwk.Set.
func NewKeySet(
	ctx context.Context,
	url string,
	opts ...cache.Option,
) jwk.Set {
	cache := cache.New(ctx, url, mapper, opts...)
	return &cachedSet{cache: cache}
}
