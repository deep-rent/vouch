package middleware

import (
	"net/http"

	"github.com/deep-rent/vouch/internal/util"
)

// Health allows probing CouchDB's health check endpoint without passing
// through other middleware. The last handler is the proxy that forwards
// the request to the upstream service.
//
// Apply this middleware if CouchDB allows unauthenticated access to the
// _up endpoint.
func Health(last http.Handler) Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if util.DB(r.URL.Path) == "_up" {
				last.ServeHTTP(w, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}
