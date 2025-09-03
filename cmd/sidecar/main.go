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
		log.Error("couldn't load config", "error", err)
		os.Exit(1)
	}

	h, err := proxy.New(cfg.Proxy.Target)
	if err != nil {
		log.Error("failed to init proxy", "error", err)
		os.Exit(1)
	}

	grd, err := auth.NewGuard(cfg)
	if err != nil {
		log.Error("failed to init guard", "error", err)
		os.Exit(1)
	}

	srv := server.New(h,
		middleware.Forward(log, grd, cfg.Proxy.Headers),
		middleware.Recover(log),
	)

	fatal := make(chan error, 1)
	go func() {
		fatal <- srv.Start(cfg.Proxy.Listen)
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
	case <-ctx.Done():
		timeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err := srv.Shutdown(timeout)
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Error("graceful shutdown failed", "error", err)
			os.Exit(1)
		}
		<-fatal
	}
}
