package middleware

import "net/http"

// Middleware wraps a HTTP handler to form a middleware chain.
type Middleware func(http.Handler) http.Handler

// Chain composes middleware handlers (outermost first).
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
