package boot

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deep-rent/vouch/internal/gateway"
)

type App struct {
	gw     gateway.Gateway
	logger *slog.Logger
}

func NewApp() (*App, error) {
	return &App{
		gw:     nil,
		logger: nil,
	}, nil
}

func (a *App) Run() error {
	errCh := make(chan error, 1)
	sigCh := make(chan os.Signal, 1)

	go func() {
		errCh <- a.gw.Start()
	}()

	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-errCh: // Server crashed
		if err != nil {
			return err
		}

	case sig := <-sigCh: // System signaled shutdown
		a.logger.Info("shutdown signal received", "signal", sig.String())

		wait, cancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer cancel()

		if err := a.gw.Stop(wait); err != nil {
			return err
		}
	}

	return nil
}

func Run(string) {}
