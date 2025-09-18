package middleware

import (
	"net/http"

	"github.com/deep-rent/vouch/internal/auth"
)

// Auth enforces authentication and authorization using the provided Guard.
func Auth(guard auth.Guard) Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if guard.Permits(w, r) {
				next.ServeHTTP(w, r)
			}
		})
	}
}
