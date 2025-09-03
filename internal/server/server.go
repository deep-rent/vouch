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
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/deep-rent/vouch/internal/middleware"
	"github.com/deep-rent/vouch/internal/proxy"
)

type Server struct {
	srv *http.Server
	mux *http.ServeMux
	url string
	cli *http.Client
}

func New(target string, mws ...middleware.Middleware) (*Server, error) {
	h, err := proxy.New(target)
	if err != nil {
		return nil, fmt.Errorf("create proxy: %w", err)
	}
	url, err := url.JoinPath(target, "_up")
	if err != nil {
		return nil, fmt.Errorf("build up url: %w", err)
	}
	s := &Server{
		mux: http.NewServeMux(),
		url: url,
		cli: &http.Client{Timeout: 2 * time.Second},
	}
	s.routes(h, mws...)
	return s, nil
}

func (s *Server) routes(h http.Handler, mws ...middleware.Middleware) {
	// Unprotected readiness and liveness probes
	s.mux.HandleFunc("GET /ready", s.ready)
	s.mux.HandleFunc("HEAD /ready", s.ready)
	s.mux.HandleFunc("GET /healthy", s.healthy)
	s.mux.HandleFunc("HEAD /healthy", s.healthy)

	// Pass CORS preflight straight through to CouchDB
	s.mux.Handle("OPTIONS /{path...}", h)

	// Everything else goes through the middleware chain and to CouchDB
	s.mux.Handle("/", middleware.Chain(h, mws...))
}

func (s *Server) ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	res, err := s.cli.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("health check returned %d", res.StatusCode)
}

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

func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv == nil {
		return nil
	}
	return s.srv.Shutdown(ctx)
}

func (s *Server) healthy(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
	_, _ = res.Write([]byte("healthy"))
}

func (s *Server) ready(res http.ResponseWriter, req *http.Request) {
	ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
	defer cancel()

	if err := s.ping(ctx); err != nil {
		http.Error(res, "not ready", http.StatusServiceUnavailable)
		return
	}
	res.WriteHeader(http.StatusOK)
	_, _ = res.Write([]byte("ready"))
}
