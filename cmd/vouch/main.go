package main

import (
	"context"
	"os"
	"time"

	"github.com/deep-rent/nexus/app"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/deep-rent/vouch/internal/gateway"
	"github.com/deep-rent/vouch/internal/server"
	"github.com/deep-rent/vouch/internal/stamper"
)

func main() {
	logger := log.New(log.WithLevel("info"), log.WithFormat(log.FormatJSON))

	runnable := func(ctx context.Context) error {
		bouncer := bouncer.New(&bouncer.Config{
			JWKS:               "",
			Issuers:            []string{},
			Audiences:          []string{},
			Leeway:             time.Minute,
			MaxAge:             time.Hour,
			UserAgent:          "Vouch",
			Timeout:            10 * time.Second,
			MinRefreshInterval: time.Minute,
			MaxRefreshInterval: 8 * time.Hour,
			AuthScheme:         "Bearer",
			RolesClaim:         "_couchdb.roles",
			Logger:             logger,
		})

		stamper := stamper.New(&stamper.Config{
			UserNameHeader: "X-Auth-CouchDB-UserName",
			RolesHeader:    "X-Auth-CouchDB-Roles",
		})

		gateway := gateway.New(&gateway.Config{
			Bouncer:       bouncer,
			Stamper:       stamper,
			URL:           nil,
			FlushInterval: -1,
			Logger:        logger,
		})

		s := server.New(&server.Config{
			Handler:           gateway,
			Host:              "",
			Port:              "8080",
			ReadHeaderTimeout: time.Second,
			ReadTimeout:       time.Second,
			WriteTimeout:      time.Second,
			IdleTimeout:       time.Second,
			Logger:            logger,
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
