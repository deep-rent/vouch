package di

import (
	"fmt"
	"reflect"
	"sync"
)

// Resolver defines a strategy for resolving service instances.
type Resolver interface {
	// Resolve provides an instance of the service within a scope.
	Resolve(in *Injector, provider any, slot any) (any, error)
}

// singleton is a Resolver that caches the instance after the first call.
type singleton struct {
	instance any
	err      error
	once     sync.Once
}

// Resolve implements the Resolver interface.
func (s *singleton) Resolve(in *Injector, provider any, slot any) (any, error) {
	s.once.Do(func() { s.instance, s.err = provide(in, provider, slot) })
	return s.instance, s.err
}

// Singleton returns a Resolver that creates an instance once and reuses it
// thereafter.
func Singleton() Resolver {
	return &singleton{}
}

// transient is a Resolver that creates a new instance on every call.
type transient struct{}

// Resolve implements the Resolver interface.
func (transient) Resolve(in *Injector, provider any, slot any) (any, error) {
	return provide(in, provider, slot)
}

// provide safely executes provider using reflection.
func provide(in *Injector, provider any, slot any) (any, error) {
	var instance any
	var err error
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf(
				"panic during provider call for slot %v: %v",
				slot, rec,
			)
			instance = nil
		}
	}()

	val := reflect.ValueOf(provider)
	out := val.Call([]reflect.Value{reflect.ValueOf(in)})
	if out[1].IsNil() {
		instance = out[0].Interface()
	} else {
		err = out[1].Interface().(error)
	}

	return instance, err
}

// Transient returns a Resolver that creates a new instance on every call.
func Transient() Resolver {
	return transient{}
}
