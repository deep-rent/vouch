package auth

import (
	"errors"
	"log/slog"
	"net/http"
)

type Guard interface {
	Permits(w http.ResponseWriter, r *http.Request) bool
}

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

type guard struct {
	bouncer Bouncer
	stamper Stamper
	logger  *slog.Logger
}

type GuardOption func(*guard)

func WithLogger(logger *slog.Logger) GuardOption {
	return func(g *guard) {
		if logger != nil {
			g.logger = logger
		}
	}
}

func (g *guard) Permits(w http.ResponseWriter, r *http.Request) bool {
	logger := g.logger.With("method", r.Method, "path", r.URL.Path)
	access, err := g.bouncer.Check(r)

	var e *AuthenticationError
	if errors.As(err, &e) {
		logger.Debug("Authentication failed", "error", e.Cause)
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	if err != nil {
		logger.Error("Unexpected error bouncing request", "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		return false
	}

	if access.Denied() {
		logger.Debug("Authorization failed")
		w.WriteHeader(http.StatusForbidden)
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
