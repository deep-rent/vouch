package middleware

import (
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Catch converts panics into a 500 Internal Server Error response, and logs
// the incident.
//
// This middleware should be put at the top of the middleware chain, so that
// it can catch panics from all downstream handlers.
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
