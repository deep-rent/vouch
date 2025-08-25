package traefikplugincouchdb

import (
	"context"
	"net/http"
)

// Config holds the plugin configuration.
type Config struct {
	// ...
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		// ...
	}
}

// Middleware is the HTTP middleware.
type Middleware struct {
	next http.Handler
	name string
	cfg  *Config
}

// Ensure Middleware implements http.Handler.
var _ http.Handler = (*Middleware)(nil)

// New creates a new Middleware.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config == nil {
		config = CreateConfig()
	}
	return &Middleware{
		next: next,
		name: name,
		cfg:  config,
	}, nil
}

func (m *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Pass the request to the next handler in the chain.
	m.next.ServeHTTP(rw, req)
}
