package listener

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/deep-rent/vouch/internal/middleware"
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
	// DefaultMaxHeaderBytes is the default maximum size of request headers (64 KiB).
	DefaultMaxHeaderBytes = 1 << 16
)

// Listener represents a HTTP server.
type Listener interface {
	// Start runs the HTTP server. It blocks until the server is
	// shut down (e.g., by Stop()) or an unrecoverable error occurs.
	Start() error

	// Stop gracefully shuts down the server, waiting for existing
	// connections to complete within the given context's deadline.
	Stop(ctx context.Context) error
}

// New creates a new Listener backed by a http.Server.
func New(opts ...Option) Listener {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	// Combine host and port to build the network address
	cfg.server.Addr = net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port))

	// Wire middleware into the server
	cfg.server.Handler = middleware.Link(cfg.server.Handler, cfg.middleware...)

	return &listener{
		server: cfg.server,
		logger: cfg.logger.With("name", "Listener"),
	}
}

// config holds the listener configuration.
type config struct {
	host       string
	port       int
	server     *http.Server
	logger     *slog.Logger
	middleware []middleware.Pipe
}

// defaultConfig creates a config with optimized defaults.
func defaultConfig() *config {
	return &config{
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

// Listener defines a function for setting listener options.
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
// If empty, it binds to all available interfaces.
// Defaults to DefaultHost.
func WithHost(h string) Option {
	return func(cfg *config) {
		cfg.host = h
	}
}

// WithPort sets the host for the server to bind to.
//
// If outside the valid port range, this option will be ignored.
// Defaults to DefaultPort.
func WithPort(p int) Option {
	return func(cfg *config) {
		if p > 0 && p <= 65535 {
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
// A non-positive value disables the timeout.
// Defaults to DefaultReadTimeout.
func WithReadTimeout(d time.Duration) Option {
	return func(cfg *config) {
		cfg.server.ReadTimeout = d
	}
}

// WithReadHeaderTimeout is the default maximum duration for reading only the
// request headers.
// A non-positive value disables the timeout.
// Defaults to DefaultReadHeaderTimeout.
func WithReadHeaderTimeout(d time.Duration) Option {
	return func(cfg *config) {
		cfg.server.ReadHeaderTimeout = d
	}
}

// WithIdleTimeout specifies the maximum amount of time to wait for the next
// request when keep-alives are enabled.
// A non-positive value disables the timeout.
// Defaults to DefaultIdleTimeout.
func WithIdleTimeout(d time.Duration) Option {
	return func(cfg *config) {
		cfg.server.IdleTimeout = d
	}
}

// WithMaxHeaderBytes sets the server's MaxHeaderBytes.
// Non-positive values are ignored and DefaultMaxHeaderBytes is used.
func WithMaxHeaderBytes(n int) Option {
	return func(cfg *config) {
		if n > 0 {
			cfg.server.MaxHeaderBytes = n
		}
	}
}

// WithTLSConfig sets the server's tls.Config for HTTPS.
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
func WithMiddleware(pipes ...middleware.Pipe) Option {
	return func(cfg *config) {
		cfg.middleware = append(cfg.middleware, pipes...)
	}
}

// WithLogger sets the logger for the listener.
// If nil, this option is ignored and slog.Default() is used.
func WithLogger(logger *slog.Logger) Option {
	return func(cfg *config) {
		if logger != nil {
			cfg.logger = logger
		}
	}
}

// listener is the internal implementation of the Listener interface.
type listener struct {
	server *http.Server
	logger *slog.Logger
}

func (l *listener) Start() error {
	l.logger.Info("starting server", "address", l.server.Addr)

	if err := l.server.ListenAndServe(); err != nil &&
		!errors.Is(err, http.ErrServerClosed) {
		l.logger.Error("server exited with error", "error", err)
		return err
	}

	l.logger.Info("server stopped")
	return nil
}

func (l *listener) Stop(ctx context.Context) error {
	l.logger.Info("stopping server")

	if err := l.server.Shutdown(ctx); err != nil {
		l.logger.Error("server shutdown failed", "error", err)
		return err
	}

	l.logger.Info("server stopped gracefully")
	return nil
}
