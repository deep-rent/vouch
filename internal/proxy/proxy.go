package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultScheme is the default target scheme.
	DefaultScheme = "http"
	// DefaultHost is the default target hostname.
	DefaultHost = "localhost"
	// DefaultPort is the default target port.
	DefaultPort = 5984
	// DefaultPath is the default target path.
	DefaultPath = ""
	// DefaultFlushInterval is the default interval for periodic flushing.
	DefaultFlushInterval = 200 * time.Millisecond
	// DefaultMinBufferSize is the default minimum size of pooled buffers.
	DefaultMinBufferSize = 32 << 10 // 32 KiB
	// DefaultMaxBufferSize is the default maximum size of pooled buffers.
	DefaultMaxBufferSize = 256 << 10 // 256 KiB
)

// New creates a new reverse proxy handler configured by the given options.
func New(opts ...Option) http.Handler {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	transport := cfg.transport
	// Rely on the HTTP_PROXY and NO_PROXY environment variables
	transport.Proxy = http.ProxyFromEnvironment
	// CouchDB currently does not support HTTP/2; attempting the upgrade
	// would only add latency
	transport.ForceAttemptHTTP2 = false
	// Disable transparent decompression to keep the upstream encoding
	transport.DisableCompression = true

	// Assemble the final target URL from its parts
	target := &url.URL{
		Scheme: cfg.scheme,
		Host:   net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port)),
		Path:   cfg.path,
	}

	log := cfg.log.With("name", "Proxy")
	log.Info("proxying to upstream target", "url", target.String())

	h := httputil.NewSingleHostReverseProxy(target)
	h.ErrorHandler = cfg.errorHandler(log)
	h.Transport = cfg.transport
	h.FlushInterval = cfg.flushInterval
	h.BufferPool = NewBufferPool(cfg.minBufferSize, cfg.maxBufferSize)
	h.Director = cfg.director(h.Director)

	return h
}

// config holds the configurable settings for the proxy handler.
type config struct {
	scheme        string
	host          string
	port          int
	path          string
	transport     *http.Transport
	flushInterval time.Duration
	minBufferSize int
	maxBufferSize int
	director      DirectorFactory
	errorHandler  ErrorHandlerFactory
	log           *slog.Logger
}

// defaultConfig initializes a configuration object with default settings.
func defaultConfig() config {
	return config{
		scheme:        DefaultScheme,
		host:          DefaultHost,
		port:          DefaultPort,
		path:          DefaultPath,
		transport:     &http.Transport{},
		flushInterval: DefaultFlushInterval,
		minBufferSize: DefaultMinBufferSize,
		maxBufferSize: DefaultMaxBufferSize,
		director:      NewDirector,
		errorHandler:  NewErrorHandler,
		log:           slog.Default(),
	}
}

// Option defines a function for setting reverse proxy options.
type Option func(*config)

// WithScheme sets the scheme (e.g., "http" or "https") for the
// upstream target.
//
// If empty, this option is ignored.
// Defaults to DefaultScheme.
func WithScheme(s string) Option {
	return func(cfg *config) {
		if s = strings.TrimSpace(s); s != "" {
			cfg.scheme = s
		}
	}
}

// WithScheme sets the hostname (e.g., "localhost" or "couchdb.internal")
// for the upstream target.
//
// Empty values are ignored, and DefaultHost is used.
func WithHost(h string) Option {
	return func(cfg *config) {
		if h = strings.TrimSpace(h); h != "" {
			cfg.host = h
		}
	}
}

// WithPort sets the port (e.g., 5984) for the upstream target.
//
// Values outside the valid port range (1-65535) will be ignored, and
// DefaultPort is used.
func WithPort(p int) Option {
	return func(cfg *config) {
		if p > 0 && p <= 65535 {
			cfg.port = p
		}
	}
}

// WithPath sets the base path (e.g., "/api") for the upstream target.
//
// This path is prepended to the incoming request path.
// Empty values are allowed. If no specified, DefaultPath is used.
func WithPath(p string) Option {
	return func(cfg *config) {
		cfg.path = strings.TrimSpace(p)
	}
}

// WithTransport sets the base http.Transport for upstream requests.
//
// If nil is given, this option is ignored.
//
// The proxy will modify this transport's Proxy, ForceAttemptHTTP2,
// and DisableCompression fields. Use this option to tune timeouts and the
// connection pool.
func WithTransport(t *http.Transport) Option {
	return func(cfg *config) {
		if t != nil {
			cfg.transport = t
		}
	}
}

// WithFlushInterval specifies the periodic flush interval for copying the
// response body to the client.
//
// This option intentionally ignores non-positive values, using
// DefaultFlushInterval by default.
//
// While the underlying proxy normally uses zero to disable flushing (which is
// detrimental to long-lived streams) or negative values to flush after each
// write, this is often unnecessary. The proxy is already smart enough to
// detect and flush true streaming responses (like the _changes feed in
// continuous mode) immediately, regardless of this setting. Instead, we retain
// a positive interval as a "safety net" to ensure low latency for other slow
// but non-streaming responses, such as large attachments or complex views.
func WithFlushInterval(d time.Duration) Option {
	return func(cfg *config) {
		if d > 0 {
			cfg.flushInterval = d
		}
	}
}

// WithMinBufferSize specifies the minimum size of buffers allocated by the
// buffer pool. This helps to reduce allocations for large response bodies.
//
// Non-positive values are ignored, and DefaultMinBufferSize is used. The
// value will be capped at MaxBufferSize.
//
// The pool will automatically adjust itself for larger, common responses
// and the MaxBufferSize will protect from memory bloat. You only need to
// adapt this setting if you know from profiling that 99% of your responses
// are, for example, larger than 100 KB.
func WithMinBufferSize(n int) Option {
	return func(cfg *config) {
		if n > 0 {
			cfg.minBufferSize = n
		}
	}
}

// WithMaxBufferSize specifies the maximum size of buffers to keep in the
// buffer pool. Buffers that grow larger than this size will be discarded
// after use to prevent memory bloat.
//
// Non-positive values are ignored, and DefaultMaxBufferSize is used.
//
// This is a critical tuning parameter. If your typical (e.g., P95)
// response size is larger than this value, the pool will be
// ineffective, as most buffers will be discarded instead of being reused.
func WithMaxBufferSize(n int) Option {
	return func(cfg *config) {
		if n > 0 {
			cfg.maxBufferSize = n
		}
	}
}

// WithDirector provides a custom DirectorFactory for the proxy.
//
// If nil is given, this option is ignored. By default, NewDirector is used.
func WithDirector(f DirectorFactory) Option {
	return func(cfg *config) {
		if f != nil {
			cfg.director = f
		}
	}
}

// WithErrorHandler provides a custom ErrorHandlerFactory for the proxy.
//
// If nil is given, this option is ignored. By default, NewErrorHandler is used.
func WithErrorHandler(f ErrorHandlerFactory) Option {
	return func(cfg *config) {
		if f != nil {
			cfg.errorHandler = f
		}
	}
}

// WithLogger provides a custom logger for the proxy's ErrorHandler.
//
// If nil is given, this option is ignored. By default, slog.Default() is used.
func WithLogger(log *slog.Logger) Option {
	return func(cfg *config) {
		if log != nil {
			cfg.log = log
		}
	}
}

// Director defines a function to modify the request before it is sent to the
// upstream target.
//
// The signature matches httputil.ReverseProxy.Director.
type Director func(*http.Request)

// DirectorFactory creates a Director using the provided original Director.
// The returned Director may call original to retain its behavior.
type DirectorFactory = func(original Director) Director

// NewDirector is the default DirectorFactory for the proxy.
// It returns the original Director unmodified.
func NewDirector(original Director) Director {
	// The default director need not be overridden; it already sets the
	// X-Forwarded-Host and X-Forwarded-Proto headers, which is exactly
	// what CouchDB expects. It also correctly rewrites the Host header
	// to match the target (required for the sidecar setup to function)
	return original
}

// ErrorHandler defines a function for handling errors that occur during the
// reverse proxy's operation.
//
// The signature matches httputil.ReverseProxy.ErrorHandler.
type ErrorHandler = func(http.ResponseWriter, *http.Request, error)

// ErrorHandlerFactory creates an ErrorHandler using the provided logger.
type ErrorHandlerFactory = func(*slog.Logger) ErrorHandler

// NewErrorHandler is the default ErrorHandlerFactory for the proxy.
// It creates an error handler that logs upstream errors using
// the provided logger and maps them to appropriate HTTP status codes.
func NewErrorHandler(log *slog.Logger) ErrorHandler {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, context.Canceled) {
			// Silence client-initiated disconnects; there's nothing useful to send
			return
		}

		status := http.StatusBadGateway
		method, uri := r.Method, r.RequestURI

		if errors.Is(err, context.DeadlineExceeded) {
			// 504 Gateway Timeout
			status = http.StatusGatewayTimeout
			log.Error(
				"upstream request timed out",
				"method", method, "uri", uri,
			)
		} else {
			// 502 Bad Gateway for everything else
			log.Error(
				"upstream request failed",
				"method", method, "uri", uri, "error", err,
			)
		}

		w.WriteHeader(status)
	}
}
