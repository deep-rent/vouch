package token

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v3/jwk"

	"github.com/deep-rent/vouch/internal/cache"
)

var (
	// Predefined KeySet errors.
	errImmutable = errors.New("set is read-only")      // immutability violation
	errNotLoaded = errors.New("set is not yet loaded") // cache not ready
)

// KeySet is an alias of jwk.Set.
type KeySet jwk.Set

// keySet wraps a refreshing cache to provide an immutable,
// nil-safe implementation of the KeySet interface.
type keySet struct{ cache *cache.Cache[KeySet] }

// cached returns the currently cached KeySet, which may be nil if the cache
// has not yet been populated.
func (s *keySet) cached() jwk.Set {
	return s.cache.Get()
}

func (s *keySet) AddKey(jwk.Key) error {
	return errImmutable
}

func (s *keySet) Clear() error {
	return errImmutable
}

func (s *keySet) Set(string, any) error {
	return errImmutable
}

func (s *keySet) Remove(string) error {
	return errImmutable
}

func (s *keySet) RemoveKey(jwk.Key) error {
	return errImmutable
}

func (s *keySet) Key(i int) (jwk.Key, bool) {
	set := s.cached()
	if set != nil {
		return set.Key(i)
	}
	return nil, false
}

func (s *keySet) Get(k string, v any) error {
	set := s.cached()
	if set != nil {
		return set.Get(k, v)
	}
	return errNotLoaded
}

func (s *keySet) Index(key jwk.Key) int {
	set := s.cached()
	if set != nil {
		return set.Index(key)
	}
	return -1
}

func (s *keySet) Len() int {
	set := s.cached()
	if set != nil {
		return set.Len()
	}
	return 0
}

func (s *keySet) LookupKeyID(id string) (jwk.Key, bool) {
	set := s.cached()
	if set != nil {
		return set.LookupKeyID(id)
	}
	return nil, false
}

func (s *keySet) Keys() []string {
	set := s.cached()
	if set != nil {
		return set.Keys()
	}
	return []string{}
}

func (s *keySet) Clone() (jwk.Set, error) {
	set := s.cached()
	if set != nil {
		return set.Clone()
	}
	return nil, errNotLoaded
}

// Assert at compile time that *keySet satisfies the KeySet interface.
var _ KeySet = (*keySet)(nil)

// mapper transforms the response body into a KeySet.
var mapper cache.Mapper[KeySet] = func(body []byte) (KeySet, error) {
	return jwk.Parse(body)
}

// NewKeySet creates a new auto-refreshing, immutable KeySet.
func NewKeySet(
	ctx context.Context,
	url string,
	opts ...cache.Option,
) KeySet {
	cache := cache.New(ctx, url, mapper, opts...)
	return &keySet{cache: cache}
}
