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
	"time"

	"github.com/deep-rent/vouch/internal/middleware"
	"github.com/deep-rent/vouch/internal/proxy"
)

// Server wraps an http.Server and reverse proxy, wiring middleware and
// exposing health/readiness endpoints.
type Server struct {
	srv   *http.Server
	mux   *http.ServeMux
	probe *probe
}

// New constructs a Server that forwards to the given CouchDB target address.
// Middlewares are applied outermost-first around the proxy handler.
func New(target *url.URL, mws ...middleware.Middleware) *Server {
	s := &Server{
		mux:   http.NewServeMux(),
		probe: newProbe(target),
	}
	s.routes(proxy.New(target), mws...)
	return s
}

// routes registers public health endpoints and the proxy handler.
func (s *Server) routes(h http.Handler, mws ...middleware.Middleware) {
	// Unprotected readiness and liveness probes.
	s.mux.HandleFunc("GET /ready", s.probe.ready)
	s.mux.HandleFunc("HEAD /ready", s.probe.ready)
	s.mux.HandleFunc("GET /healthy", s.probe.healthy)
	s.mux.HandleFunc("HEAD /healthy", s.probe.healthy)

	// Pass CORS preflight straight through to CouchDB.
	s.mux.Handle("OPTIONS /{path...}", h)

	// Everything else goes through the middleware chain and to CouchDB.
	s.mux.Handle("/", middleware.Chain(h, mws...))
}

// Start runs the HTTP server on addr and blocks until the server stops.
// It returns nil on graceful shutdown, or the terminal error otherwise.
func (s *Server) Start(addr string) error {
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      0, // Allow streaming responses
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64 KB
	}

	err := s.srv.ListenAndServe()
	if !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown attempts a graceful server shutdown within ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}
