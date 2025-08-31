package main

import (
	"flag"
	"log/slog"
	"os"

	"github.com/deep-rent/vouch/internal/config"
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

	pxy, err := proxy.New(cfg.Target)
	if err != nil {
		slog.Error("Failed to init proxy handler", "error", err)
		os.Exit(1)
	}

	srv := server.New(pxy)
	if err := srv.Start(cfg.Source); err != nil {
		slog.Error("Server runtime error", "error", err)
		os.Exit(1)
	}

	slog.Info("Exited gracefully")
}
