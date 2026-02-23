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
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/deep-rent/nexus/app"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/nexus/updater"
	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/gateway"
	"github.com/deep-rent/vouch/internal/server"
	"github.com/deep-rent/vouch/internal/stamper"
)

// The application version injected via -ldflags during build time.
var version = "v0.0.0"

func main() {
	if err := boot(context.Background(), os.Args, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func boot(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(stdout)

	showVersion := flags.Bool("v", false, "Display version and exit")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	if *showVersion {
		_, _ = fmt.Fprintf(stdout, "Vouch %s\n", version)
		return nil
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	logger := log.New(log.WithLevel(cfg.LogLevel), log.WithFormat(cfg.LogFormat))
	ua := fmt.Sprintf("Vouch/%s", version)

	if cfg.UpdateCheck {
		go func() {
			rel, err := updater.Check(ctx, &updater.Config{
				Owner:      "deep-rent",
				Repository: "vouch",
				Current:    version,
				UserAgent:  ua,
			})

			if err != nil {
				logger.Warn("Could not check for newer release", slog.Any("error", err))
			} else if rel != nil {
				logger.Info(
					"New release available",
					slog.String("version", rel.Version),
					slog.String("url", rel.URL),
				)
			}
		}()
	}

	// Initialize the Bouncer to handle JWT verification and JWKS caching.
	bouncer := bouncer.New(&bouncer.Config{
		TokenIssuers:            cfg.TokenIssuers,
		TokenAudiences:          cfg.TokenAudiences,
		TokenLeeway:             cfg.TokenLeeway,
		TokenMaxAge:             cfg.TokenMaxAge,
		TokenAuthScheme:         cfg.TokenAuthScheme,
		TokenRolesClaim:         cfg.TokenRolesClaim,
		KeysURL:                 cfg.KeysURL,
		KeysUserAgent:           ua,
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

	serve := func(ctx context.Context) error {
		errCh := make(chan error, 1)
		go func() { errCh <- s.Start() }()
		select {
		case err := <-errCh:
			return err
		case <-ctx.Done():
			// Gracefully stop the server on context cancellation.
			if err := s.Stop(); err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		}
	}

	fetch := func(ctx context.Context) error {
		return bouncer.Start(ctx)
	}

	components := []app.Runnable{serve, fetch}

	// Spin up the HTTP server and the JWKS refresh loop concurrently.
	if err := app.RunAll(
		components,
		app.WithContext(ctx),
		app.WithLogger(logger),
	); err != nil {
		return err
	}

	return nil
}
