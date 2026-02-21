package main

import (
	"context"
	"net"
	"net/http"
	"os"
	"time"

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
			Addr:    net.JoinHostPort(cfg.Host, cfg.Port),
			Handler: guard.New(&guard.Config{}),
			// Strictly rely on CouchDB to close connections.
			WriteTimeout: 0,
			// Drop slow clients early without affecting long polling or large payload
			// uploads.
			ReadHeaderTimeout: 5 * time.Second,
			// If you allow very large document uploads (e.g., attachments), ensure
			// this is long enough to receive the payload. If you only expect small
			// JSON documents, keep it tight.
			ReadTimeout: 30 * time.Second,
			// Controls the keep-alive time between the external client and the proxy.
			IdleTimeout: 2 * time.Minute,
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
