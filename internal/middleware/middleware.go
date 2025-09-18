package middleware

import "net/http"

// Pipe wraps a HTTP handler to form a middleware chain for adding
// cross-cutting behavior.
type Pipe func(http.Handler) http.Handler

// Link composes middlewares into a chain (outermost first).
func Link(h http.Handler, pipes ...Pipe) http.Handler {
	// Apply in reverse so the first middleware wraps last.
	for i := len(pipes) - 1; i >= 0; i-- {
		h = pipes[i](h)
	}
	return h
}
