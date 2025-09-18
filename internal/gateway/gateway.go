package gateway

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/deep-rent/vouch/internal/middleware"
	"github.com/deep-rent/vouch/internal/util"
)

const (
	// DefaultHost is the default host to bind to.
	DefaultHost = "" // all interfaces
	// DefaultPort is the default port to listen on.
	DefaultPort = 8080
	// DefaultReadTimeout is the default maximum duration for reading the
	// entire request, including the body.
	DefaultReadTimeout = 30 * time.Second
	// DefaultReadHeaderTimeout is the default maximum duration for reading
	// only the request headers.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultIdleTimeout is the default maximum amount of time to wait for the
	// next request when keep-alives are enabled.
	DefaultIdleTimeout = 90 * time.Second
	// DefaultMaxHeaderBytes is the default maximum size of request headers.
	DefaultMaxHeaderBytes = 1 << 16 // 64 KiB
)

// Gateway represents a HTTP server that listens for incoming traffic to be
// proxied to CouchDB.
type Gateway interface {
	// Start runs the HTTP server. It blocks until the server is
	// shut down (e.g., by Stop()) or an unrecoverable error occurs.
	Start() error

	// Stop gracefully shuts down the server, waiting for existing
	// connections to complete within the given context's deadline.
	Stop(ctx context.Context) error
}

// New creates a new Gateway backed by a http.Server.
func New(opts ...Option) Gateway {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	// Combine host and port to build the network address
	cfg.server.Addr = net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port))

	// Wire middleware into the server
	cfg.server.Handler = middleware.Link(cfg.server.Handler, cfg.middleware...)

	return &gateway{
		server: cfg.server,
		logger: cfg.logger.With("name", "Gateway"),
	}
}

// config holds the gateway configuration.
type config struct {
	host       string
	port       int
	server     *http.Server
	logger     *slog.Logger
	middleware []middleware.Pipe
}

// defaultConfig initializes a configuration object with optimized defaults.
func defaultConfig() config {
	return config{
		host: DefaultHost,
		port: DefaultPort,
		server: &http.Server{
			ReadTimeout:                  DefaultReadTimeout,
			ReadHeaderTimeout:            DefaultReadHeaderTimeout,
			WriteTimeout:                 0, // Support streaming responses
			IdleTimeout:                  DefaultIdleTimeout,
			MaxHeaderBytes:               DefaultMaxHeaderBytes,
			DisableGeneralOptionsHandler: true,
		},
		logger:     slog.Default(),
		middleware: make([]middleware.Pipe, 0, 5),
	}
}

// Option defines a function for setting gateway options.
type Option func(*config)

// WithServer replaces the underlying http.Server with a custom one.
//
// If nil is given, this option is ignored.
//
// Warning: This option is intended for testing and mocks only, as it can
// conflict with other options.
func WithServer(s *http.Server) Option {
	return func(cfg *config) {
		if s != nil {
			cfg.server = s
		}
	}
}

// WithHost sets the host for the server to bind to.
//
// If empty, it binds to all available interfaces. Defaults to DefaultHost.
func WithHost(h string) Option {
	return func(cfg *config) {
		cfg.host = strings.TrimSpace(h)
	}
}

// WithPort sets the port for the server to bind to.
//
// Values outside the valid port range will be ignored, and DefaultPort is used.
func WithPort(p int) Option {
	return func(cfg *config) {
		if util.Port(p) {
			cfg.port = p
		}
	}
}

// WithHandler sets the base http.Handler for the server. This should
// be the reverse proxy handler.
//
// Middleware will be wrapped around this handler. If nil, this option will
// be ignored.
func WithHandler(h http.Handler) Option {
	return func(cfg *config) {
		if h != nil {
			cfg.server.Handler = h
		}
	}
}

// WithReadHeaderTimeout is the default maximum duration for reading the
// entire request, including the body.
//
// Non-positive values are ignored. By default, the timeout is set to
// DefaultReadTimeout. Note that a zero would usually disable the timeout,
// but this is not allowed here to prevent accidental misconfiguration.
func WithReadTimeout(d time.Duration) Option {
	return func(cfg *config) {
		if d > 0 {
			cfg.server.ReadTimeout = d
		}
	}
}

// WithReadHeaderTimeout is the default maximum duration for reading only the
// request headers.
//
// Non-positive values are ignored. By default, the timeout is set to
// DefaultReadHeaderTimeout. Note that a zero would usually disable the timeout,
// but this is not allowed here to prevent accidental misconfiguration.
func WithReadHeaderTimeout(d time.Duration) Option {
	return func(cfg *config) {
		if d > 0 {
			cfg.server.ReadHeaderTimeout = d
		}
	}
}

// WithIdleTimeout specifies the maximum amount of time to wait for the next
// request when keep-alives are enabled.
//
// Non-positive values are ignored. By default, the timeout is set to
// DefaultIdleTimeout. Note that a zero would usually disable the timeout,
// but this is not allowed here to prevent accidental misconfiguration.
func WithIdleTimeout(d time.Duration) Option {
	return func(cfg *config) {
		cfg.server.IdleTimeout = d
	}
}

// WithMaxHeaderBytes sets the server's MaxHeaderBytes.
//
// Non-positive values are ignored and DefaultMaxHeaderBytes is used.
func WithMaxHeaderBytes(n int) Option {
	return func(cfg *config) {
		if n > 0 {
			cfg.server.MaxHeaderBytes = n
		}
	}
}

// WithTLSConfig sets the server's tls.Config for HTTPS.
//
// If nil, this option is ignored.
func WithTLSConfig(tls *tls.Config) Option {
	return func(cfg *config) {
		if tls != nil {
			cfg.server.TLSConfig = tls
		}
	}
}

// WithMiddleware appends one or more middleware pipes to the server's
// handler chain. Middleware is applied in the order it is provided
// (outermost first).
//
// This option can be called multiple times to add more middleware.
func WithMiddleware(pipes ...middleware.Pipe) Option {
	return func(cfg *config) {
		cfg.middleware = append(cfg.middleware, pipes...)
	}
}

// WithLogger sets the logger to notify about the gateway's lifecycle events.
//
// If nil, this option is ignored and slog.Default() is used.
func WithLogger(logger *slog.Logger) Option {
	return func(cfg *config) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}

// gateway is the internal implementation of the Gateway interface.
type gateway struct {
	server *http.Server
	logger *slog.Logger
}

// Start implements the Gateway interface.
func (g *gateway) Start() error {
	g.logger.Info("starting server", "address", g.server.Addr)

	if err := g.server.ListenAndServe(); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		g.logger.Error("server exited with error", "error", err)
		return err
	}

	g.logger.Info("server stopped")
	return nil
}

// Stop implements the Gateway interface.
func (g *gateway) Stop(ctx context.Context) error {
	g.logger.Info("stopping server")

	if err := g.server.Shutdown(ctx); err != nil {
		g.logger.Error("server shutdown failed", "error", err)
		return err
	}

	g.logger.Info("server stopped gracefully")
	return nil
}
