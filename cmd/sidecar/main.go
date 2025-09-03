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

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/middleware"
	"github.com/deep-rent/vouch/internal/server"
)

func main() {
	path := flag.String(
		"c",
		"./config.yaml",
		"Path to the YAML configuration file",
	)
	verb := flag.String(
		"v",
		"info",
		"Verbosity: debug, info, warn, error",
	)

	flag.Parse()

	level, err := toLevel(*verb)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(2)
	}

	log := slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{
			Level: level,
		},
	))
	slog.SetDefault(log)

	log.Info("loading config", "path", *path)

	cfg, err := config.Load(*path)
	if err != nil {
		log.Error("couldn't load config", "error", err)
		os.Exit(1)
	}

	headers := cfg.Proxy.Headers
	if headers.Secret == "" {
		log.Warn("proxy signing secret not configured")
	}

	grd, err := auth.NewGuard(context.Background(), cfg)
	if err != nil {
		log.Error("failed to init guard", "error", err)
		os.Exit(1)
	}

	target := cfg.Proxy.Target
	listen := cfg.Proxy.Listen

	srv, err := server.New(
		target,
		middleware.Recover(log),
		middleware.Forward(log, grd, headers),
	)
	if err != nil {
		log.Error("failed to create server", "error", err)
		os.Exit(1)
	}

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
		if err != nil {
			log.Error("server exited with error", "error", err)
			os.Exit(1)
		}
		log.Info("server stopped")
	case <-ctx.Done():
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

func toLevel(s string) (slog.Level, error) {
	switch s {
	case "debug":
		return slog.LevelDebug, nil
	case "info":
		return slog.LevelInfo, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown level: %s", s)
	}
}
