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
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(log)

	path := flag.String(
		"config",
		"./config.yaml",
		"Path to the YAML configuration file",
	)
	flag.Parse()

	cfg, err := config.Load(*path)
	if err != nil {
		log.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	h, err := proxy.New(cfg.Proxy.Target)
	if err != nil {

		os.Exit(1)
	}

	guard, err := auth.NewGuard(cfg)
	if err != nil {
		log.Error("Failed to init auth guard", "error", err)
		os.Exit(1)
	}

	auth, err := middleware.NewAuth(
		guard,
		cfg.Proxy.Headers,
	)
	if err != nil {
		log.Error("Failed to init auth middleware", "error", err)
		os.Exit(1)
	}

	srv := server.New(h, auth, middleware.Recover(log))
	if err := srv.Start(cfg.Proxy.Listen); err != nil {
		log.Error("Server runtime error", "error", err)
		os.Exit(1)
	}

	log.Info("Exited gracefully")
}
