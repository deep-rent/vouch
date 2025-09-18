package middleware

import "net/http"

// Preflight allows CORS preflight requests (OPTIONS) to bypass other
// middleware. The last handler is the proxy that forwards the request to
// the upstream service.
//
// Apply this middleware if CouchDB has CORS enabled.
func Preflight(last http.Handler) Pipe {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions {
				last.ServeHTTP(w, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}
