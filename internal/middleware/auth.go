package middleware

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/signer"
	"github.com/deep-rent/vouch/internal/token"
)

func NewAuth(guard *auth.Guard, cfg config.Headers) (Middleware, error) {
	signer := signer.New(cfg.Secret)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			// Let CORS preflight pass through unchanged
			if req.Method == http.MethodOptions {
				next.ServeHTTP(res, req)
				return
			}

			scope, err := guard.Check(req)
			if err == auth.ErrForbidden {
				res.WriteHeader(http.StatusForbidden)
				return
			}
			var unauthorized *token.AuthenticationError
			if errors.As(err, &unauthorized) {
				res.Header().Set("WWW-Authenticate", unauthorized.Challenge)
				res.WriteHeader(http.StatusUnauthorized)
				return
			}
			if err != nil {
				slog.Error("", "error", err)
				return
			}

			if user := scope.User; user != "" {
				res.Header().Set(cfg.User, user)

				if role := scope.Role; role != "" {
					res.Header().Set(cfg.Roles, role)
				}
				if signer != nil {
					res.Header().Set(cfg.Token, signer.Sign(user))
				}
			}

			next.ServeHTTP(res, req)
		})
	}, nil
}
