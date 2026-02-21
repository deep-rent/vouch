package main

import (
	"context"
	"os"

	"github.com/deep-rent/nexus/app"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/vouch/internal/server"
)

func main() {
	logger := log.New(
		log.WithLevel("info"),
	)

	runnable := func(ctx context.Context) error {
		s := server.New(&server.Config{
			Logger: logger,
		})
		go s.Start()
		<-ctx.Done()
		return s.Stop()
	}

	if err := app.Run(runnable, app.WithLogger(logger)); err != nil {
		logger.Error("Application failed", "error", err)
		os.Exit(1)
	}
}
