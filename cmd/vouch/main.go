package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/deep-rent/nexus/app"
	"github.com/deep-rent/nexus/log"
)

func main() {
	logger := log.New(
		// TODO: Fetch log level and format from environment configuration
		log.WithLevel("info"),
		log.WithFormat("text"),
	)

	runnable := func(ctx context.Context) error {
		// Starting application
		<-ctx.Done()
		// Shutting down
		return nil
	}

	if err := app.Run(runnable, app.WithLogger(logger)); err != nil {
		logger.Error("Failed to run application", slog.Any("error", err))
		os.Exit(1)
	}
}
