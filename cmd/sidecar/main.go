package main

import (
	"context"
	"errors"
	"flag"
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
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)

	path := flag.String(
		"config",
		"./config.yaml",
		"Path to the YAML configuration file",
	)
	flag.Parse()

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
