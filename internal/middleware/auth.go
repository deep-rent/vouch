package middleware

import (
	"log/slog"
	"net/http"

	"github.com/deep-rent/vouch/internal/auth"
)

func Auth(guard auth.Guard, logger *slog.Logger) Pipe {
	logger = logger.With("name", "middleware.Auth")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := guard.Handle(w, r); err != nil {
				logger.Debug("Access denied", "error", err)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}
