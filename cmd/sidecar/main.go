package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/middleware"
	"github.com/deep-rent/vouch/internal/proxy"
	"github.com/deep-rent/vouch/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	path := flag.String(
		"config",
		"./config.yaml",
		"Path to the YAML configuration file",
	)
	flag.Parse()

	cfg, err := config.Load(*path)
	if err != nil {
		slog.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	h, err := proxy.New(cfg.Proxy.Target)
	if err != nil {

		os.Exit(1)
	}

	guard, err := auth.NewGuard(cfg)
	if err != nil {
		slog.Error("Failed to init auth guard", "error", err)
		os.Exit(1)
	}

	auth, err := middleware.NewAuth(
		guard,
		cfg.Proxy.Headers,
	)
	if err != nil {
		slog.Error("Failed to init auth middleware", "error", err)
		os.Exit(1)
	}

	srv := server.New(h, auth)
	if err := srv.Start(cfg.Proxy.Listen); err != nil {
		slog.Error("Server runtime error", "error", err)
		os.Exit(1)
	}

	slog.Info("Exited gracefully")
}
