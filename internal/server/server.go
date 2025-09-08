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

	"github.com/deep-rent/vouch/internal/middleware"
	"github.com/deep-rent/vouch/internal/proxy"
)

// Server wraps an http.Server and reverse proxy, wiring middleware and
// exposing health/readiness endpoints.
type Server interface {
	// Start runs the HTTP server on addr and blocks until the server stops.
	// It returns nil on graceful shutdown, or the terminal error otherwise.
	Start(addr string) error
	// Shutdown attempts to stop the server gracefully within the given context.
	Shutdown(ctx context.Context) error
}

// server is the concrete implementation of Server.
type server struct {
	srv *http.Server // guarded by mu
	mu  sync.Mutex
	mux *http.ServeMux
}

// New constructs a Server that forwards to the given CouchDB target address.
// Middlewares are applied outermost-first around the proxy handler.
func New(target *url.URL, mws ...middleware.Middleware) Server {
	s := &server{
		mux: http.NewServeMux(),
	}
	s.routes(proxy.New(target), mws...)
	return s
}

// routes registers the proxy handler, exempting passthrough routes
// from middleware protection.
func (s *server) routes(h http.Handler, mws ...middleware.Middleware) {
	// Pass CORS preflight straight through to CouchDB.
	s.mux.Handle("OPTIONS /{path...}", h)

	// Pass through CouchDB's own readiness probe.
	s.mux.Handle("GET /_up", h)
	s.mux.Handle("HEAD /_up", h)

	// Everything else goes through the middleware chain and to CouchDB.
	s.mux.Handle("/", middleware.Chain(h, mws...))
}

func (s *server) Start(addr string) error {
	s.mu.Lock()
	if s.srv != nil {
		s.mu.Unlock()
		return nil
	}
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0, // Allow streaming responses
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KB
	}
	s.mu.Unlock()

	err := s.srv.ListenAndServe()
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
	return srv.Shutdown(wt)
}
