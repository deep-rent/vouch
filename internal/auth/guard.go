package auth

import (
	"log/slog"
	"net/http"
)

// Guard checks incoming HTTP requests for proper authentication and
// authorization prior to proxying them to CouchDB.
type Guard interface {
	// Permits inspects the given HTTP request and writes an appropriate HTTP
	// response if the request is not authorized. It returns true if the request
	// is permitted to proceed to CouchDB.
	Permits(w http.ResponseWriter, r *http.Request) bool
}

// NewGuard creates a new Guard using the given Bouncer and Stamper. Additional
// options can be provided to customize its behavior.
func NewGuard(bouncer Bouncer, stamper Stamper, opts ...GuardOption) Guard {
	g := &guard{
		bouncer: bouncer,
		stamper: stamper,
		logger:  slog.Default(),
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// guard is the default implementation of Guard.
// It uses a Bouncer to authorize requests and a Stamper to augment them with
// CouchDB user context.
type guard struct {
	bouncer Bouncer
	stamper Stamper
	logger  *slog.Logger
}

// GuardOption configures a Guard.
type GuardOption func(*guard)

// WithLogger sets a custom logger for the Guard.
//
// If nil is given, this option is ignored. By default, slog.Default() is used.
func WithLogger(logger *slog.Logger) GuardOption {
	return func(g *guard) {
		if logger != nil {
			g.logger = logger
		}
	}
}

// Permits implements the Guard interface.
func (g *guard) Permits(w http.ResponseWriter, r *http.Request) bool {
	logger := g.logger.With("method", r.Method, "path", r.URL.Path)
	access, err := g.bouncer.Check(r)

	// Currently, AccessError is guaranteed to be top-level. If this changes, we
	// may need to switch to errors.As to find it in the error stack.
	if e, ok := err.(*AccessError); ok {
		logger.Debug("Access denied", "error", e)
		w.WriteHeader(e.StatusCode())
		return false
	}

	if err != nil {
		logger.Error("Unexpected error bouncing request", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return false
	}

	if err := g.stamper.Stamp(r, access); err != nil {
		logger.Error("Unexpected error stamping request", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return false
	}

	logger.Debug("Access granted", "user", access.User, "roles", access.Roles)
	return true
}
