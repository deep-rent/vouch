package main

import (
	"context"
	"os"
	"time"

	"github.com/deep-rent/nexus/app"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/gateway"
	"github.com/deep-rent/vouch/internal/server"
	"github.com/deep-rent/vouch/internal/stamper"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		panic(err.Error())
	}

	logger := log.New(log.WithLevel(cfg.Level), log.WithFormat(cfg.Format))

	runnable := func(ctx context.Context) error {
		bouncer := bouncer.New(&bouncer.Config{
			JWKS:               cfg.JWKS,
			Issuers:            cfg.Issuers,
			Audiences:          cfg.Audiences,
			Leeway:             cfg.Leeway,
			MaxAge:             cfg.MaxAge,
			UserAgent:          cfg.UserAgent,
			Timeout:            cfg.Timeout,
			MinRefreshInterval: cfg.MinRefreshInterval,
			MaxRefreshInterval: cfg.MaxRefreshInterval,
			AuthScheme:         cfg.AuthScheme,
			RolesClaim:         cfg.RolesClaim,
			Logger:             logger,
		})

		stamper := stamper.New(&stamper.Config{
			UserNameHeader: cfg.UserNameHeader,
			RolesHeader:    cfg.RolesHeader,
		})

		gateway := gateway.New(&gateway.Config{
			Bouncer:         bouncer,
			Stamper:         stamper,
			URL:             cfg.URL,
			FlushInterval:   -1,
			MinBufferSize:   0,
			MaxBufferSize:   0,
			MaxIdleConns:    0,
			IdleConnTimeout: time.Second,
			Logger:          logger,
		})

		s := server.New(&server.Config{
			Handler:           gateway,
			Host:              cfg.Host,
			Port:              cfg.Port,
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
			MaxHeaderBytes:    cfg.MaxHeaderBytes,
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
