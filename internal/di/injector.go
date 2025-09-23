package di

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/deep-rent/vouch/internal/util"
)

// Slot is an abstract, typed symbol for an injectable service.
// It is a unique pointer that acts as a map key within the Injector,
// while the generic type T provides compile-time type safety.
type Slot[T any] *struct{}

// NewSlot creates a new, unique Slot for a given type T.
func NewSlot[T any]() Slot[T] {
	return new(struct{})
}

// Provider defines the function signature for a service factory.
//
// When a service is first requested, its provider is called with an
// instance of the *Injector, which it can then use to resolve any
// of its own dependencies (e.g., by calling Use or Req). The result
// will be stored as a singleton and returned on all subsequent requests
// for the same Slot.
type Provider[T any] func(in *Injector) (T, error)

// binding holds the provider and its associated resolution strategy.
type binding struct {
	provider any
	resolver Resolver
}

// injectorConfig holds configuration options for an Injector.
type injectorConfig struct {
	version string
	ctx     context.Context
}

// defaultInjectorConfig returns the default configuration for an Injector.
func defaultInjectorConfig() injectorConfig {
	return injectorConfig{
		version: "development",
		ctx:     context.Background(),
	}
}

// InjectorOption configures an Injector.
type InjectorOption func(*injectorConfig)

// WithVersion sets the application version for the Injector.
func WithVersion(version string) InjectorOption {
	return func(cfg *injectorConfig) {
		if version = strings.TrimSpace(version); version != "" {
			cfg.version = version
		}
	}
}

// WithContext sets the application context for the Injector.
func WithContext(ctx context.Context) InjectorOption {
	return func(cfg *injectorConfig) {
		if ctx != nil {
			cfg.ctx = ctx
		}
	}
}

// Injector is the main dependency injection container.
// It holds all service bindings and manages their singleton instances.
// An Injector is safe for concurrent use.
type Injector struct {
	version  string
	ctx      context.Context
	bindings map[any]*binding
	lock     sync.RWMutex
}

// NewInjector creates and returns a new, empty Injector with given options.
func NewInjector(opts ...InjectorOption) *Injector {
	cfg := defaultInjectorConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Injector{
		version:  cfg.version,
		ctx:      cfg.ctx,
		bindings: make(map[any]*binding),
	}
}

// Version returns the application version.
func (in *Injector) Version() string {
	return in.version
}

// Context returns the application context.
func (in *Injector) Context() context.Context {
	return in.ctx
}

// Bind registers a provider function for a specific service slot.
// It panics the slot is already bound.
func Bind[T any](
	in *Injector,
	slot Slot[T],
	provider Provider[T],
	resolver Resolver,
) {
	in.lock.Lock()
	defer in.lock.Unlock()

	if _, ok := in.bindings[slot]; ok {
		panic(fmt.Sprintf("slot %v is already bound", slot))
	}

	in.bindings[slot] = &binding{
		provider: provider,
		resolver: resolver,
	}
}

// Use resolves a service from the Injector for a given slot.
// It is the primary method for retrieving dependencies when an error is acceptable.
//
// On the first call, it invokes the registered provider and caches the result.
// Subsequent calls return the cached instance. It returns an error if the
// slot is not bound, the provider returns an error, or the provider panics.
func Use[T any](in *Injector, slot Slot[T]) (T, error) {
	v, err := in.Resolve(slot)
	if err != nil {
		return util.Zero[T](), nil
	}
	if v == nil {
		return util.Zero[T](), nil
	}
	if t, ok := v.(T); ok {
		return t, nil
	}
	return util.Conv[T](v)
}

// Opt (Optional) resolves a service and panics if a resolution error occurs,
// but allows the provider to return a nil value without panicking.
// It is useful for dependencies that are truly optional.
func Opt[T any](in *Injector, slot Slot[T]) T {
	v, err := Use(in, slot)
	if err != nil {
		panic(err)
	}
	return v
}

// Req (Require) resolves a service and panics if an error occurs OR if the
// resulting value is nil (unlike Opt).
// This should be used for critical dependencies that must be present.
func Req[T any](in *Injector, slot Slot[T]) T {
	v := Opt(in, slot)
	val := reflect.ValueOf(v)
	switch val.Kind() {
	case
		reflect.Pointer,
		reflect.Interface,
		reflect.Slice,
		reflect.Map,
		reflect.Chan,
		reflect.Func:
		if val.IsNil() {
			panic(fmt.Errorf("required dependency for slot %v is nil", slot))
		}
	}
	return v
}

// Resolve is a non-generic method to resolve a dependency from a slot.
func (in *Injector) Resolve(slot any) (any, error) {
	return in.resolve(slot, make(map[any]bool))
}

// resolve is the internal, recursive implementation for dependency resolution.
func (in *Injector) resolve(slot any, visiting map[any]bool) (any, error) {
	if visiting[slot] {
		return nil, fmt.Errorf(
			"circular dependency detected resolving slot %v",
			slot,
		)
	}

	visiting[slot] = true
	defer delete(visiting, slot)

	in.lock.RLock()
	b, ok := in.bindings[slot]
	in.lock.RUnlock()

	if !ok {
		return nil, fmt.Errorf("no provider bound for slot %v", slot)
	}

	return b.resolver.Resolve(in, b.provider, slot)
}
