package middleware

import (
	"log/slog"
	"net/http"

	"github.com/deep-rent/vouch/internal/auth"
)

// Auth enforces authentication and authorization using the provided Guard.
//
// If the Guard denies access, it is responsible for writing the appropriate
// response (e.g., 401 Unauthorized or 403 Forbidden). Otherwise, the request
// is passed to the next handler in the chain.
func Auth(guard auth.Guard, logger *slog.Logger) Pipe {
	logger = logger.With("name", "Auth")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// TODO: consider handling errors here
			if err := guard.Handle(w, r); err != nil {
				logger.Debug("Access denied", "error", err)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}
