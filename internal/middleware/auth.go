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

func Auth(log *slog.Logger, guard *auth.Guard, cfg config.Headers) Middleware {
	var sign *signer.Signer
	if secret := cfg.Secret; secret != "" {
		sign = signer.New(secret)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			// Let CORS preflight pass through unchanged
			if req.Method == http.MethodOptions {
				next.ServeHTTP(res, req)
				return
			}

			scope, err := guard.Check(req)
			if err == auth.ErrForbidden {
				code := http.StatusForbidden
				http.Error(res, http.StatusText(code), code)
				return
			}
			var unauthorized *token.AuthenticationError
			if errors.As(err, &unauthorized) {
				res.Header().Set("WWW-Authenticate", unauthorized.Challenge)
				code := http.StatusUnauthorized
				http.Error(res, http.StatusText(code), code)
				return
			}
			if err != nil {
				log.Error("auth check failed", "error", err)
				code := http.StatusInternalServerError
				http.Error(res, http.StatusText(code), code)
				return
			}

			if user := scope.User; user != "" {
				res.Header().Set(cfg.User, user)

				if role := scope.Role; role != "" {
					res.Header().Set(cfg.Roles, role)
				}
				if sign != nil {
					res.Header().Set(cfg.Token, sign.Sign(user))
				}
			}

			next.ServeHTTP(res, req)
		})
	}
}
