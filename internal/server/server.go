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

package server

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/middleware"
	"github.com/deep-rent/vouch/internal/proxy"
)

// Server wraps an HTTP server that proxies requests to CouchDB.
type Server interface {
	// Start runs the HTTP server and blocks until the server stops.
	// It returns nil on graceful shutdown, or the terminal error otherwise.
	Start() error
	// Shutdown attempts to stop the server gracefully within the given context.
	Shutdown(ctx context.Context) error
	// Listen returns the address the server is listening on.
	Listen() string
	// Target returns the CouchDB target address the server proxies to.
	Target() string
	// Handler exposes the HTTP handler for testing or embedding.
	Handler() http.Handler
}

// ErrAlreadyRunning is returned by Start if the server is already running.
var ErrAlreadyRunning = errors.New("server already running")

// server is the concrete implementation of Server.
type server struct {
	mux  *http.ServeMux
	srv  *http.Server
	out  *url.URL
	runs bool // guarded by mu
	mu   sync.Mutex
}

// New constructs a Server that forwards to the given CouchDB target address.
// Middlewares are applied outermost-first around the proxy handler.
func New(cfg config.Server, mws ...middleware.Middleware) Server {
	mux := http.NewServeMux()
	s := &server{
		mux: mux,
		srv: &http.Server{
			Addr:              cfg.Local.Addr,
			Handler:           mux,
			ReadTimeout:       30 * time.Second,
			ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout:      0, // Allow streaming responses
			IdleTimeout:       90 * time.Second,
			MaxHeaderBytes:    1 << 16, // 64 KB
		},
		out: cfg.Proxy.Target,
	}
	s.routes(mws...)
	return s
}

func (s *server) Listen() string        { return s.srv.Addr }
func (s *server) Target() string        { return s.out.String() }
func (s *server) Handler() http.Handler { return s.mux }

// routes registers the proxy handler, exempting passthrough routes
// from middleware protection.
func (s *server) routes(mws ...middleware.Middleware) {
	h := proxy.New(s.out)

	// Pass CORS preflight straight through to CouchDB.
	s.mux.Handle("OPTIONS /{path...}", h)

	// Pass through CouchDB's own readiness probe.
	s.mux.Handle("GET /_up", h)
	s.mux.Handle("HEAD /_up", h)

	// Everything else goes through the middleware chain and to CouchDB.
	s.mux.Handle("/", middleware.Chain(h, mws...))
}

func (s *server) Start() error {
	s.mu.Lock()
	if s.runs {
		s.mu.Unlock()
		return ErrAlreadyRunning
	}
	s.runs = true
	srv := s.srv
	s.mu.Unlock()

	err := srv.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	wt, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err := srv.Shutdown(wt)

	// Allow restart after a graceful shutdown.
	s.mu.Lock()
	s.runs = false
	s.mu.Unlock()

	return err
}
