// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
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

// Package gateway implements the reverse proxy logic, orchestrating
// authentication and request forwarding.
package gateway

import (
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/proxy"
	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/deep-rent/vouch/internal/stamper"
)

// Config holds the configuration for the Gateway.
type Config struct {
	Bouncer         *bouncer.Bouncer
	Stamper         *stamper.Stamper
	URL             *url.URL
	FlushInterval   time.Duration
	MinBufferSize   int
	MaxBufferSize   int
	MaxIdleConns    int
	IdleConnTimeout time.Duration
	Logger          *slog.Logger
}

// Gateway is an http.Handler that authenticates requests using a Bouncer,
// stamps them with a Stamper, and proxies them to a backend.
type Gateway struct {
	bouncer *bouncer.Bouncer
	stamper *stamper.Stamper
	backend http.Handler
	logger  *slog.Logger
}

// New creates a new Gateway handler.
func New(cfg *Config) http.Handler {
	handler := proxy.NewHandler(
		cfg.URL,
		// For long polling, such as CouchDB's _changes feed, we want to flush as
		// soon as possible (set to -1 to disable buffering entirely). Otherwise,
		// buffering will delay heartbeats (newlines) or event chunks, causing
		// client timeouts.
		proxy.WithFlushInterval(cfg.FlushInterval),
		// Optimize the request buffer to avoid garbage collection pressure under
		// heavy load.
		proxy.WithMinBufferSize(cfg.MinBufferSize),
		proxy.WithMaxBufferSize(cfg.MaxBufferSize),
		proxy.WithTransport(&http.Transport{
			// For a sidecar, this should match or exceed the expected peak of
			// concurrent requests.
			MaxIdleConns: cfg.MaxIdleConns,
			// Since we are only proxying to one host, this is equal to MaxIdleConns.
			MaxIdleConnsPerHost: cfg.MaxIdleConns,
			// We wish to reuse connections as much as possible, but we also need to
			// eventually prune that CouchDB might have silently dropped.
			IdleConnTimeout: cfg.IdleConnTimeout,

			DisableCompression: true,  // CouchDB compresses responses when requested.
			ForceAttemptHTTP2:  false, // CouchDB doesn't support HTTP/2.
		}),
		proxy.WithLogger(cfg.Logger),
	)

	return &Gateway{
		bouncer: cfg.Bouncer,
		stamper: cfg.Stamper,
		backend: handler,
		logger:  cfg.Logger,
	}
}

// ServeHTTP handles the HTTP request lifecycle: authenticate, stamp, and proxy.
func (h *Gateway) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	// Authenticate the request.
	pass, err := h.bouncer.Bounce(req)
	if err != nil {
		h.logger.DebugContext(
			req.Context(),
			"Request denied",
			slog.Any("error", err),
		)
		res.WriteHeader(http.StatusUnauthorized)
		return
	}
	// Inject identity headers.
	h.stamper.Stamp(req, pass)
	// Forward to the backend.
	h.backend.ServeHTTP(res, req)
}
