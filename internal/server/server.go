package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/deep-rent/vouch/internal/guard"
)

type Config struct {
	Guard             *guard.Config
	Host              string
	Port              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	Logger            *slog.Logger
}

type Server struct {
	server *http.Server
	logger *slog.Logger
}

func New(cfg *Config) *Server {
	return &Server{
		server: &http.Server{
			Addr:              net.JoinHostPort(cfg.Host, cfg.Port),
			Handler:           guard.New(cfg.Guard),
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
		},
		logger: cfg.Logger,
	}
}

func (s *Server) Start() {
	s.logger.Info("Server listening", "address", s.server.Addr)
	if err := s.server.ListenAndServe(); err != nil &&
		err != http.ErrServerClosed {
		s.logger.Error("Server failed", "error", err)
	}
}

func (s *Server) Stop() error {
	return s.server.Shutdown(context.Background())
}
