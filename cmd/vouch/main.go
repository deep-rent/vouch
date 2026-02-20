package main

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/deep-rent/nexus/app"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/forward"
)

func main() {
	// Load configuration.
	cfg, err := config.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger.
	logger := log.New(log.WithLevel(cfg.Level))

	runnable := func(ctx context.Context) error {
		logger.Info("Vouch proxy starting...")

		// Initialize authenticator.
		authenticator := auth.New(cfg)

		// Initialize proxy handler.
		proxy := forward.New(authenticator, cfg, logger)

		// Create HTTP server.
		server := &http.Server{
			Addr:    fmt.Sprintf(":%s", cfg.Port),
			Handler: proxy,
		}

		// Start server in a goroutine.
		go func() {
			logger.Info("Server listening", "port", cfg.Port)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Error("Server failed", "error", err)
			}
		}()

		// Wait for stop signal.
		<-ctx.Done()
		logger.Info("Shutting down server...")

		// Shutdown the server.
		return server.Shutdown(context.Background())
	}

	if err := app.Run(runnable, app.WithLogger(logger)); err != nil {
		logger.Error("Application failed", "error", err)
		os.Exit(1)
	}
}
