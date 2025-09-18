package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Catch wraps a handler and converts panics into a 500 Internal Server Error.
func Catch(logger *slog.Logger) Pipe {
	logger = logger.With("name", "middleware.Catch")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				// Intercept a panic from downstream handlers.
				if err := recover(); err != nil {
					logger.Error(
						"An unhandled panic occurred",
						"method", r.Method,
						"path", r.URL.Path,
						"error", err,
						"stack", string(debug.Stack()),
					)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}
