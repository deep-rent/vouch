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

// Command vouch starts the authentication sidecar and reverse proxy
// for CouchDB. It authenticates inbound requests using access tokens,
// enforces authorization rules, and forwards requests to the
// configured CouchDB target.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/logger"
	"github.com/deep-rent/vouch/internal/middleware"
	"github.com/deep-rent/vouch/internal/server"
)

// version is set at build time using -ldflags "-X main.version=..."
var version = "dev"

// flags is the data model for the command line arguments.
type flags struct {
	path    string // path to config file
	version bool   // show version
}

// parse parses the command line arguments and returns them.
func parse() (*flags, error) {
	path := strings.TrimSpace(os.Getenv("VOUCH_CONFIG"))
	if path == "" {
		// Fall back to the default config file path.
		path = "./config.yaml"
	}
	p := new(flags)
	f := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ContinueOnError)
	f.StringVar(&p.path, "c", path, "Path to the YAML config file (alias: --config)")
	f.BoolVar(&p.version, "v", false, "Show version and exit (alias: --version)")

	// Map long-form aliases to their short-form counterparts.
	args := os.Args[1:]
	for i, arg := range args {
		switch {
		case arg == "--config":
			args[i] = "-c"
		case strings.HasPrefix(arg, "--config="):
			args[i] = "-c=" + strings.TrimPrefix(arg, "--config=")
		case arg == "--version":
			args[i] = "-v"
		}
	}

	err := f.Parse(args)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// main is the entry point for this command.
func main() {
	log := logger.New(os.Getenv("VOUCH_LOG"))
	slog.SetDefault(log)

	f, err := parse()
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0) // Print help exits successfully.
		}
		log.Error("invalid arguments", "error", err)
		os.Exit(2)
	}

	if f.version {
		fmt.Printf("version: %s\n", version)
		os.Exit(0)
	}

	if err := run(f); err != nil {
		log.Error("application error", "error", err)
		os.Exit(1)
	}
}

// run executes the main application logic.
func run(f *flags) error {
	log := slog.Default()
	log.Info("loading config", "path", f.path)

	// Load and validate the configuration.
	cfg, err := config.Load(f.path)
	if err != nil {
		return fmt.Errorf("couldn't load config: %w", err)
	}

	// Warn if CouchDB proxy signing is not configured.
	if cfg.Proxy.Headers.Secret == "" {
		log.Warn("proxy signing secret not configured")
	}

	// Application-scoped context for background components.
	appCtx, appCancel := context.WithCancel(context.Background())
	defer appCancel()

	// Construct the authentication and authorization guard.
	grd, err := auth.NewGuard(appCtx, cfg)
	if err != nil {
		return fmt.Errorf("failed to init guard: %w", err)
	}

	// Wire proxy and middleware into the server.
	srv := server.New(
		cfg.Proxy.Target,
		middleware.Recover(log),
		middleware.Forward(log, grd, cfg.Proxy.Headers),
	)

	// Run the server and handle termination signals for graceful shutdown.
	errch := make(chan error, 1)
	go func() {
		log.Info("starting server",
			"listen", cfg.Proxy.Listen,
			"target", cfg.Proxy.Target,
		)
		errch <- srv.Start(cfg.Proxy.Listen)
	}()

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	select {
	case err := <-errch:
		// Ensure background work is stopped if the server exits.
		appCancel()
		if err != nil {
			return fmt.Errorf("server exited with error: %w", err)
		}
		log.Info("server stopped")
	case <-ctx.Done():
		// Stop background work first, then shut down the server.
		appCancel()
		log.Info("server shutting down")
		if err := srv.Shutdown(context.Background()); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("graceful shutdown failed", "error", err)
		}
		<-errch // Wait for server to stop.
		log.Info("server stopped")
	}
	return nil
}
