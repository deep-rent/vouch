package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/deep-rent/nexus/app"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/guard"
)

func main() {
	cfg := &config.Config{}
	logger := log.New(
		log.WithLevel("info"),
	)
	cfg.Logger = logger

	runnable := func(ctx context.Context) error {
		server := &http.Server{
			Addr:    fmt.Sprintf(":%s", cfg.Port),
			Handler: guard.New(cfg),
		}

		go func() {
			logger.Info("Server listening", "port", cfg.Port)
			if err := server.ListenAndServe(); err != nil &&
				err != http.ErrServerClosed {
				logger.Error("Server failed", "error", err)
			}
		}()

		<-ctx.Done()
		return server.Shutdown(context.Background())
	}

	if err := app.Run(runnable, app.WithLogger(logger)); err != nil {
		logger.Error("Application failed", "error", err)
		os.Exit(1)
	}
}
