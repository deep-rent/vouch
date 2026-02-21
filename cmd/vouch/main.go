package main

import (
	"context"
	"os"

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

	logger := log.New(log.WithLevel(cfg.LogLevel), log.WithFormat(cfg.LogFormat))

	runnable := func(ctx context.Context) error {
		bouncer := bouncer.New(&bouncer.Config{
			JWKS:               cfg.KeySetURL,
			Issuers:            cfg.TokenIssuers,
			Audiences:          cfg.TokenAudiences,
			Leeway:             cfg.TokenLeeway,
			MaxAge:             cfg.TokenMaxAge,
			UserAgent:          cfg.KeySetUserAgent,
			Timeout:            cfg.KeySetTimeout,
			MinRefreshInterval: cfg.KeySetMinRefreshInterval,
			MaxRefreshInterval: cfg.KeySetMaxRefreshInterval,
			AuthScheme:         cfg.TokenAuthScheme,
			RolesClaim:         cfg.TokenRolesClaim,
			Logger:             logger,
		})

		stamper := stamper.New(&stamper.Config{
			UserNameHeader: cfg.UserNameHeader,
			RolesHeader:    cfg.RolesHeader,
		})

		gateway := gateway.New(&gateway.Config{
			Bouncer:         bouncer,
			Stamper:         stamper,
			URL:             cfg.Target,
			FlushInterval:   cfg.FlushInterval,
			MinBufferSize:   cfg.MinBufferSize,
			MaxBufferSize:   cfg.MaxBufferSize,
			MaxIdleConns:    cfg.MaxIdleConns,
			IdleConnTimeout: cfg.IdleConnTimeout,
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
