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

package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/middleware"
)

type Config struct {
	Handler           http.Handler
	Host              string
	Port              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
	Logger            *slog.Logger
}

type Server struct {
	server *http.Server
	logger *slog.Logger
}

func New(cfg *Config) *Server {
	// Collect middleware to apply to the handler.
	pipes := []middleware.Pipe{middleware.Recover(cfg.Logger)}

	// Only add logging middleware if debug logging is enabled, to avoid the
	// overhead of logging every request when it's not necessary.
	if cfg.Logger.Enabled(context.Background(), slog.LevelDebug) {
		pipes = append(pipes, middleware.Log(cfg.Logger))
	}

	return &Server{
		server: &http.Server{
			Addr:              net.JoinHostPort(cfg.Host, cfg.Port),
			Handler:           middleware.Chain(cfg.Handler, pipes...),
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
			MaxHeaderBytes:    cfg.MaxHeaderBytes,
			ErrorLog: slog.NewLogLogger(
				cfg.Logger.Handler(),
				slog.LevelError,
			),
		},
		logger: cfg.Logger,
	}
}

func (s *Server) Start() error {
	host, port, _ := net.SplitHostPort(s.server.Addr)
	s.logger.Info(
		"Server listening",
		slog.String("host", host),
		slog.String("port", port),
	)
	return s.server.ListenAndServe()
}

func (s *Server) Stop() error {
	return s.server.Shutdown(context.Background())
}
