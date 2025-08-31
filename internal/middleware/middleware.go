package middleware

import "net/http"

func Apply(h http.Handler) http.Handler {
	return chain(h, auth)
}

// chain composes middleware handlers (outermost first).
func chain(h http.Handler, mws ...func(http.Handler) http.Handler) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}
