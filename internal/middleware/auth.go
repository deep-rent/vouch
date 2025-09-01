package middleware

import (
	"net/http"
	"strings"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/guard"
	"github.com/deep-rent/vouch/internal/rule"
)

func NewAuth(cfg *config.Config) (Middleware, error) {
	g, err := guard.New(cfg.Rules)
	if err != nil {
		return nil, err
	}

	userHeader := strings.TrimSpace(cfg.Headers.User)
	if userHeader == "" {
		userHeader = "X-Auth-CouchDB-UserName"
	}

	roleHeader := strings.TrimSpace(cfg.Headers.Role)
	if roleHeader == "" {
		roleHeader = "X-Auth-CouchDB-Roles"
	}

	hashHeader := strings.TrimSpace(cfg.Headers.Hash)
	if hashHeader == "" {
		hashHeader = "X-Auth-CouchDB-Token"
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			// Let CORS preflight pass through unchanged
			if req.Method == http.MethodOptions {
				next.ServeHTTP(res, req)
				return
			}

			// Build evaluation environment
			env := rule.NewEnvironment(nil, req)

			pass, user, role, err := g.Authorize(env)

			if err != nil {
				http.Error(res, "Failed to authorize request", http.StatusInternalServerError)
				return
			}

			if !pass {
				http.Error(res, "Insufficient permissions", http.StatusForbidden)
				return
			}

			if user != "" {
				res.Header().Set(userHeader, user)
			}
			if role != "" {
				res.Header().Set(roleHeader, role)
			}

			next.ServeHTTP(res, req)
		})
	}, nil
}
