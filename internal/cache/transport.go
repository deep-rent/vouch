package cache

import "net/http"

// headersTransport is a custom http.RoundTripper that adds multiple headers
// to each outgoing HTTP request.
type headersTransport struct {
	base    http.RoundTripper
	headers map[string]string // header key-value pairs
}

// SetHeaders creates a new http.RoundTripper that sets the specified
// headers on each request, then invokes the provided base.
func SetHeaders(
	base http.RoundTripper,
	headers map[string]string,
) http.RoundTripper {
	if len(headers) == 0 {
		return base
	}
	h := make(map[string]string, len(headers))
	for k, v := range headers {
		h[http.CanonicalHeaderKey(k)] = v
	}
	return &headersTransport{
		headers: h,
		base:    base,
	}
}

// RoundTrip implements the http.RoundTripper interface.
func (t *headersTransport) RoundTrip(
	req *http.Request,
) (*http.Response, error) {
	for k, v := range t.headers {
		req.Header.Set(k, v)
	}
	return t.base.RoundTrip(req)
}

// Ensure headersTransport satisfies the http.RoundTripper interface.
var _ http.RoundTripper = (*headersTransport)(nil)
