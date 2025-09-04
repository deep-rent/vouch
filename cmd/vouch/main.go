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
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/middleware"
	"github.com/deep-rent/vouch/internal/server"
)

// flags is the data model for the command line arguments.
type flags struct {
	path string // path to config file
}

// parse parses the command line arguments and returns them.
func parse() (*flags, error) {
	path := strings.TrimSpace(os.Getenv("VOUCH_CONFIG_PATH"))
	if path == "" {
		// The default config file path.
		path = "./config.yaml"
	}
	p := new(flags)
	f := flag.NewFlagSet(filepath.Base(os.Args[0]), flag.ContinueOnError)
	f.StringVar(&p.path, "c", path, "Path to the YAML config file")
	err := f.Parse(os.Args[1:])
	if err != nil {
		return nil, err
	}
	return p, nil
}

// logger sets up and returns a structured logger.
func logger() *slog.Logger {
	// Determine the logging verbosity level from the environment variable.
	l := strings.TrimSpace(os.Getenv("VOUCH_LOG_LEVEL"))
	var level slog.Level
	switch strings.ToUpper(l) {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{
			Level: level,
		},
	))
}

func main() {
	// Set up structured logging before doing any work.
	log := logger()
	slog.SetDefault(log)

	f, err := parse()
	if err != nil {
		// Print help exits successfully.
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		log.Error("failed to parse command line arguments", "error", err)
		os.Exit(2)
	}

	log.Info("loading config", "path", f.path)

	// Load and validate the configuration.
	cfg, err := config.Load(f.path)
	if err != nil {
		log.Error("couldn't load config", "error", err)
		os.Exit(1)
	}

	// Warn if CouchDB proxy signing is not configured.
	headers := cfg.Proxy.Headers
	if headers.Secret == "" {
		log.Warn("proxy signing secret not configured")
	}

	// Application-scoped context for background components.
	_ctx, _cancel := context.WithCancel(context.Background())
	defer _cancel()

	// Construct the authentication and authorization guard.
	grd, err := auth.NewGuard(_ctx, cfg)
	if err != nil {
		log.Error("failed to init guard", "error", err)
		os.Exit(1)
	}

	target := cfg.Proxy.Target
	listen := cfg.Proxy.Listen

	// Wire proxy and middleware into the server.
	srv, err := server.New(
		target,
		middleware.Recover(log),
		middleware.Forward(log, grd, headers),
	)
	if err != nil {
		log.Error("failed to create server", "error", err)
		os.Exit(1)
	}

	// Run the server and handle termination signals for graceful shutdown.
	fatal := make(chan error, 1)
	go func() {
		log.Info("starting server",
			"listen", listen,
			"target", target,
		)
		fatal <- srv.Start(listen)
	}()

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	select {
	case err := <-fatal:
		// Ensure background work is stopped if the server exits.
		_cancel()
		if err != nil {
			log.Error("server exited with error", "error", err)
			os.Exit(1)
		}
		log.Info("server stopped")
	case <-ctx.Done():
		// Stop background work first, then shut down the server.
		_cancel()
		dur := 10 * time.Second
		timeout, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		log.Info("shutting down", "timeout", dur.String())
		err := srv.Shutdown(timeout)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error("graceful shutdown failed", "error", err)
			os.Exit(1)
		}
		<-fatal
		log.Info("server stopped")
	}
}
