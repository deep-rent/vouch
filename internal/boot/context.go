package boot

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"sync/atomic"
)

const DefaultVersion = "development"

type contextConfig struct {
	version string
	ctx     context.Context
	logger  *slog.Logger
}

func defaultContextConfig() contextConfig {
	return contextConfig{
		version: DefaultVersion,
		ctx:     context.Background(),
		logger:  slog.Default(),
	}
}

type ContextOption func(*contextConfig)

func WithVersion(v string) ContextOption {
	return func(cfg *contextConfig) {
		if v = strings.TrimSpace(v); v != "" {
			cfg.version = v
		}
	}
}

func WithContext(ctx context.Context) ContextOption {
	return func(cfg *contextConfig) {
		if ctx != nil {
			cfg.ctx = ctx
		}
	}
}

func WithLogger(log *slog.Logger) ContextOption {
	return func(cfg *contextConfig) {
		if log != nil {
			cfg.logger = log
		}
	}
}

// Context assists in bootstrapping the application from configuration data
// by tracking the current location in the configuration structure, logging
// warnings and errors, and counting the total number of errors encountered.
type Context struct {
	version string
	ctx     context.Context
	root    *slog.Logger
	logger  *slog.Logger
	path    []string
	errors  *atomic.Int64
}

// NewContext creates a new Context with the given application context
// and root logger instance.
func NewContext(opts ...ContextOption) *Context {
	cfg := defaultContextConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Context{
		version: cfg.version,
		ctx:     cfg.ctx,
		root:    cfg.logger,
		logger:  cfg.logger,
		path:    []string{},
		errors:  new(atomic.Int64),
	}
}

// Context returns the application context.
func (c *Context) Context() context.Context {
	return c.ctx
}

// WithField returns a new Context with the given field added to the path.
// Invoke this method when descending into a nested configuration structure.
func (c *Context) WithField(k string) *Context {
	path := make([]string, len(c.path)+1)
	copy(path, c.path)
	path[len(c.path)] = k
	return &Context{
		ctx:    c.ctx,
		root:   c.root,
		logger: c.logger.With(slog.Any("path", path)),
		path:   path,
		errors: c.errors,
	}
}

// WithIndex returns a new Context with the given index added to the path.
// Invoke this method when descending into an array configuration structure.
func (c *Context) WithIndex(i int) *Context {
	return c.WithField("[" + strconv.Itoa(i) + "]")
}

// Error logs an error message and increments the error count.
// This method reports a configuration error that must be addressed for the
// application to start successfully.
func (c *Context) Error(msg string, args ...any) {
	c.logger.ErrorContext(c.ctx, msg, args...)
	c.errors.Add(1)
}

// Warn logs a warning message.
// This method reports a potential configuration issue that does not prevent the
// application from starting, but may be worth investigating.
func (c *Context) Warn(msg string, args ...any) {
	c.logger.WarnContext(c.ctx, msg, args...)
}

// Errors returns the total number of errors logged so far. A non-zero value
// indicates that application startup should be aborted.
func (c *Context) Errors() int64 {
	return c.errors.Load()
}

// Logger returns the root logger.
func (c *Context) Logger() *slog.Logger {
	return c.root
}
