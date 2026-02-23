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

// Package main is the entry point for the Vouch sidecar proxy application.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/deep-rent/nexus/app"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/gateway"
	"github.com/deep-rent/vouch/internal/server"
	"github.com/deep-rent/vouch/internal/stamper"
)

// The application version injected via -ldflags during build time.
var version = "dev"

// main initializes and runs the application components.
func main() {
	showVersion := flag.Bool("v", false, "Display version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	cfg, err := config.Load()
	if err != nil {
		panic(err.Error())
	}

	logger := log.New(log.WithLevel(cfg.LogLevel), log.WithFormat(cfg.LogFormat))

	runnable := func(ctx context.Context) error {
		// Initialize the Bouncer to handle JWT verification and JWKS caching.
		bouncer := bouncer.New(&bouncer.Config{
			TokenIssuers:            cfg.TokenIssuers,
			TokenAudiences:          cfg.TokenAudiences,
			TokenLeeway:             cfg.TokenLeeway,
			TokenMaxAge:             cfg.TokenMaxAge,
			TokenAuthScheme:         cfg.TokenAuthScheme,
			TokenRolesClaim:         cfg.TokenRolesClaim,
			KeysURL:                 cfg.KeysURL,
			KeysUserAgent:           fmt.Sprintf("Vouch/%s", version),
			KeysTimeout:             cfg.KeysTimeout,
			KeysMinRefreshInterval:  cfg.KeysMinRefreshInterval,
			KeysMaxRefreshInterval:  cfg.KeysMaxRefreshInterval,
			KeysAttemptLimit:        cfg.KeysAttemptLimit,
			KeysBackoffMinDelay:     cfg.KeysBackoffMinDelay,
			KeysBackoffMaxDelay:     cfg.KeysBackoffMaxDelay,
			KeysBackoffGrowthFactor: cfg.KeysBackoffGrowthFactor,
			KeysBackoffJitterAmount: cfg.KeysBackoffJitterAmount,
			Logger:                  logger,
		})

		// Initialize the Stamper to inject proxy authentication headers.
		stamper := stamper.New(&stamper.Config{
			UserNameHeader: cfg.UserNameHeader,
			RolesHeader:    cfg.RolesHeader,
		})

		// Initialize the Gateway to proxy requests to the upstream service.
		gateway := gateway.New(&gateway.Config{
			Bouncer:         bouncer,
			Stamper:         stamper,
			URL:             cfg.Target,
			FlushInterval:   cfg.FlushInterval,
			MinBufferSize:   cfg.MinBufferSize,
			MaxBufferSize:   cfg.MaxBufferSize,
			MaxIdleConns:    cfg.MaxIdleConns,
			IdleConnTimeout: cfg.IdleConnTimeout,
			Logger:          logger,
		})

		// Initialize the HTTP server.
		s := server.New(&server.Config{
			Handler:           gateway,
			Host:              cfg.Host,
			Port:              cfg.Port,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
			MaxHeaderBytes:    cfg.MaxHeaderBytes,
			Logger:            logger,
		})

		errCh := make(chan error, 1)

		// Start the HTTP server concurrently.
		go func() { errCh <- s.Start() }()

		// Schedule the background refresh of the remote JWKS.
		go func() {
			if err := bouncer.Start(ctx); err != nil {
				errCh <- err
			}
		}()

		// Wait for an error or a shutdown signal.
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			// Gracefully stop the server on context cancellation.
			err := s.Stop()
			if err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		}
	}

	if err := app.Run(runnable, app.WithLogger(logger)); err != nil {
		logger.Error("Application exited with error", slog.Any("error", err))
		os.Exit(1)
	}
}
