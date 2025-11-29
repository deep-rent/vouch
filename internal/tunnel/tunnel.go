package tunnel

import (
	"net/http"
	"net/url"
	"time"

	"github.com/deep-rent/nexus/proxy"
)

// flushInterval defines the interval for periodic flushing of the reverse
// proxy's response buffer.
//
// While the proxy normally uses zero to disable flushing (which is detrimental
// to long-lived streams) or negative values to flush after each write, this is
// often unnecessary. The proxy is already smart enough to detect and flush true
// streaming responses (like the _changes feed in continuous mode) immediately,
// regardless of this setting. Instead, we retain a positive interval as a
// "safety net" to ensure low latency for other slow but non-streaming
// responses, such as large attachments or complex views.
const flushInterval = 200 * time.Millisecond

func New(target *url.URL) proxy.Handler {
	return proxy.NewHandler(
		target,
		proxy.WithFlushInterval(flushInterval),
		// The default buffer sizes are fine for this use case.
		// proxy.WithMinBufferSize(proxy.DefaultMinBufferSize),
		// proxy.WithMaxBufferSize(proxy.DefaultMaxBufferSize),
		proxy.WithTransport(&http.Transport{
			// Rely on the HTTP_PROXY and NO_PROXY environment variables.
			Proxy: http.ProxyFromEnvironment,
			// CouchDB currently does not support HTTP/2; attempting the upgrade
			// would only add latency.
			ForceAttemptHTTP2: false,
			// Disable transparent decompression to keep the upstream encoding.
			DisableCompression: true,
		}),
	)
}
