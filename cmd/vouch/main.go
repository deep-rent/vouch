package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/deep-rent/nexus/app"
	"github.com/deep-rent/nexus/log"
	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/gateway"
	"github.com/deep-rent/vouch/internal/server"
	"github.com/deep-rent/vouch/internal/stamper"
)

var version = "dev"

func main() {
	showVersion := flag.Bool("v", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	cfg, err := config.Load()
	if err != nil {
		panic(err.Error())
	}

	logger := log.New(log.WithLevel(cfg.LogLevel), log.WithFormat(cfg.LogFormat))

	runnable := func(ctx context.Context) error {
		bouncer := bouncer.New(&bouncer.Config{
			TokenIssuers:            cfg.TokenIssuers,
			TokenAudiences:          cfg.TokenAudiences,
			TokenLeeway:             cfg.TokenLeeway,
			TokenMaxAge:             cfg.TokenMaxAge,
			TokenAuthScheme:         cfg.TokenAuthScheme,
			TokenRolesClaim:         cfg.TokenRolesClaim,
			KeysURL:                 cfg.KeysURL,
			KeysUserAgent:           cfg.KeysUserAgent,
			KeysTimeout:             cfg.KeysTimeout,
			KeysMinRefreshInterval:  cfg.KeysMinRefreshInterval,
			KeysMaxRefreshInterval:  cfg.KeysMaxRefreshInterval,
			KeysAttemptLimit:        cfg.KeysAttemptLimit,
			KeysBackoffMinDelay:     cfg.KeysBackoffMinDelay,
			KeysBackoffMaxDelay:     cfg.KeysBackoffMaxDelay,
			KeysBackoffGrowthFactor: cfg.KeysBackoffGrowthFactor,
			KeysBackoffJitterAmount: cfg.KeysBackoffJitterAmount,
			Logger:                  logger,
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

		errCh := make(chan error, 1)
		go func() {
			errCh <- s.Start()
		}()

		select {
		case err := <-errCh:
			if err != nil && err != http.ErrServerClosed {
				return err
			}
			return nil
		case <-ctx.Done():
			return s.Stop()
		}
	}

	if err := app.Run(runnable, app.WithLogger(logger)); err != nil {
		logger.Error("Application failed", "error", err)
		os.Exit(1)
	}
}
