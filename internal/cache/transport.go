package cache

import "net/http"

// headerTransport is a custom http.RoundTripper that adds a specific header
// to each outgoing HTTP request.
type headerTransport struct {
	key  string // header key
	val  string // header value
	base http.RoundTripper
}

// setHeader creates a new http.RoundTripper that sets the specified
// header (key-value pair) on each request, then invokes the provided base.
func setHeader(base http.RoundTripper, k, v string) http.RoundTripper {
	return &headerTransport{
		key:  http.CanonicalHeaderKey(k),
		val:  v,
		base: base,
	}
}

// RoundTrip implements the http.RoundTripper interface.
func (t *headerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Set the custom header on the request.
	req.Header.Set(t.key, t.val)
	// Feed the modified request into the original transport.
	return t.base.RoundTrip(req)
}

// Ensure headerTransport satisfies the http.RoundTripper interface.
var _ http.RoundTripper = (*headerTransport)(nil)
