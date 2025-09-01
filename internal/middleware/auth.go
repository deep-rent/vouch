package middleware

import (
	"net/http"

	"github.com/deep-rent/vouch/internal/guard"
	"github.com/deep-rent/vouch/internal/rule"
)

func auth(next http.Handler) http.Handler {
	g, err := guard.New(make([]rule.Config, 0))
	if err != nil {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			http.Error(res, "Failed to create guard", http.StatusInternalServerError)
		})
	}

	return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodOptions {
			next.ServeHTTP(res, req)
			return
		}

		env := rule.NewEnvironment(nil, req)

		pass, user, role, err := g.Authorize(env)

		if err != nil {
			http.Error(res, "Failed to authorize request", http.StatusForbidden)
			return
		}

		if !pass {
			http.Error(res, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if user != "" {
			res.Header().Set("X-Auth-CouchDB-UserName", user)
		}
		if role != "" {
			res.Header().Set("X-Auth-CouchDB-Roles", role)
		}

		next.ServeHTTP(res, req)
	})
}
