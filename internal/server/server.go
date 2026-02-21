package server

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/deep-rent/vouch/internal/gateway"
)

type Config struct {
	Gateway           *gateway.Config
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
			Handler:           gateway.New(cfg.Gateway),
			ReadHeaderTimeout: cfg.ReadHeaderTimeout,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			IdleTimeout:       cfg.IdleTimeout,
		},
		logger: cfg.Logger,
	}
}

func (s *Server) Start() {
	host, port, _ := net.SplitHostPort(s.server.Addr)
	s.logger.Info(
		"Server listening",
		slog.String("host", host),
		slog.String("port", port),
	)

	err := s.server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		s.logger.Error("Server failed", slog.Any("error", err))
	}
}

func (s *Server) Stop() error {
	return s.server.Shutdown(context.Background())
}
