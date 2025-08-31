package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/deep-rent/vouch/internal/middleware"
)

type Server struct {
	mux *http.ServeMux
}

func New(proxy http.Handler) *Server {
	s := &Server{
		mux: http.NewServeMux(),
	}
	s.routes(proxy)
	return s
}

func (s *Server) routes(proxy http.Handler) {
	// Unprotected health endpoint (readiness/liveness)
	s.mux.HandleFunc("/healthz", func(res http.ResponseWriter, req *http.Request) {
		res.WriteHeader(http.StatusOK)
		_, _ = res.Write([]byte("ok"))
	})

	// Everything else goes through the middleware chain and to CouchDB
	s.mux.Handle("/",
		middleware.Chain(
			proxy,
			middleware.Auth,
		),
	)
}

func (s *Server) Start(addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fail := make(chan error, 1)
	quit := make(chan os.Signal, 1)

	go func() {
		slog.Info("Starting server", "address", srv.Addr)
		if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			fail <- err
		}
	}()

	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-fail:
		return err
	case sig := <-quit:
		slog.Info("Shutdown signal received", "signal", sig.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		return err
	}

	slog.Info("Server stopped")
	return nil
}
