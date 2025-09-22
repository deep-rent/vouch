package cache

import (
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/deep-rent/vouch/internal/retry"
)

const (
	// DefaultMinInterval is the default minimum time to wait between fetches.
	DefaultMinInterval = 15 * time.Minute
	// DefaultMaxInterval is the default maximum time to wait between fetches.
	DefaultMaxInterval = 60 * time.Minute
	// DefaultTimeout is the default request timeout for the internal HTTP client.
	DefaultTimeout = 30 * time.Second
)

// Mapper defines a function that parses a raw request payload
// into a generic type T.
type Mapper[T any] func(body []byte) (T, error)

// config holds all configurable parameters for a Cache.
type config struct {
	minInterval time.Duration
	maxInterval time.Duration
	timeout     time.Duration
	headers     map[string]string
	tls         *tls.Config
	log         *slog.Logger
	backoff     retry.Backoff
	scheduler   Scheduler
	clock       func() time.Time
	client      *http.Client
}

// defaultConfig initializes a configuration object with default settings.
func defaultConfig() config {
	return config{
		timeout:     DefaultTimeout,
		headers:     make(map[string]string),
		log:         slog.Default(),
		minInterval: DefaultMinInterval,
		maxInterval: DefaultMaxInterval,
		clock:       time.Now,
	}
}

// Option defines a function for setting cache options.
type Option func(*config)

// WithMinInterval sets the minimum time to wait between fetches.
//
// Non-positive values are ignored, and DefaultMinInterval is used. The value
// will be bounded above by the maximum interval at configuration time. If
// both are equal, the cache will be refreshed at a constant rate.
func WithMinInterval(d time.Duration) Option {
	return func(cfg *config) {
		if d > 0 {
			cfg.minInterval = d
		}
	}
}

// WithMaxInterval sets the maximum time to wait between fetches.
//
// Non-positive values are ignored, and DefaultMaxInterval is used. The value
// will be bounded below by the minimum interval at configuration time. If
// both are equal, the cache will be refreshed at a constant rate.
func WithMaxInterval(d time.Duration) Option {
	return func(cfg *config) {
		if d > 0 {
			cfg.maxInterval = d
		}
	}
}

// WithTimeout sets the total request timeout for the internal HTTP client.
//
// Non-positive values are ignored, and DefaultTimeout is used. Other timeouts
// (e.g. dial, TLS handshake, response header) will be derived as fractions of
// this value when the client is created internally. Note that zero values are
// not allowed, as they disable timeouts entirely, which makes the client
// vulnerable to hanging requests.
func WithTimeout(d time.Duration) Option {
	return func(cfg *config) {
		if d > 0 {
			cfg.client.Timeout = d
		}
	}
}

// WithTLSConfig sets the internal client's TLS configuration.
//
// If nil is given, this option is ignored. By default, the system's root CAs
// are used.
func WithTLSConfig(c *tls.Config) Option {
	return func(cfg *config) {
		if c != nil {
			cfg.tls = c
		}
	}
}

// WithHeader instructs the underlying HTTP client to set a custom header
// on each outgoing request.
//
// If either the key or value is empty after trimming whitespace, this option
// is ignored. Multiple calls to this function will stack headers.
func WithHeader(k, v string) Option {
	return func(cfg *config) {
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k != "" && v != "" {
			cfg.headers[k] = v
		}
	}
}

// WithUserAgent sets the User-Agent header for all outgoing requests.
//
// It is a shorthand for WithHeader.
func WithUserAgent(v string) Option { return WithHeader("User-Agent", v) }

// WithLogger provides a custom logger for the cache.
//
// If nil is given, this option is ignored. By default, slog.Default() is used.
func WithLogger(log *slog.Logger) Option {
	return func(cfg *config) {
		if log != nil {
			cfg.log = log
		}
	}
}

// WithBackoff sets a custom backoff strategy for handling retries.
//
// If nil is given, this option is ignored. This means that calls continue to
// be repeated at the minimum interval until they succeed. In most cases, the
// delay for retries should be relatively short compared to the regular fetch
// interval. This allows for quick recovery from transient errors.
func WithBackoff(b retry.Backoff) Option {
	return func(cfg *config) {
		if b != nil {
			cfg.backoff = b
		}
	}
}

// WithScheduler allows injecting a custom scheduler.
//
// This option should only be overridden for testing.
func WithScheduler(s Scheduler) Option {
	return func(cfg *config) {
		if s != nil {
			cfg.scheduler = s
		}
	}
}

// WithClient allows injecting a custom HTTP client for fetching.
//
// This option should only be overridden for testing.
func WithClient(c *http.Client) Option {
	return func(cfg *config) {
		if c != nil {
			cfg.client = c
		}
	}
}

// WithClock allows plugging in a custom abstraction over time.Now.
//
// This option should only be overridden for testing.
func WithClock(c func() time.Time) Option {
	return func(cfg *config) {
		if c != nil {
			cfg.clock = c
		}
	}
}

// Cache stores a generic resource of type T and manages its refresh cycle.
// It periodically fetches the resource from a given URL, factoring in HTTP
// caching headers to minimize data transfer. The resource is parsed through
// a user-provided Mapper function and can be accessed via Get. All methods
// are safe for concurrent use.
type Cache[T any] struct {
	url         string
	client      *http.Client
	log         *slog.Logger
	mapper      Mapper[T]
	clock       func() time.Time
	minInterval time.Duration
	maxInterval time.Duration
	mu          sync.RWMutex       // Guards resource, etag
	resource    T                  // Assigned atomically
	etag        ETag               // Assigned atomically
	scheduler   Scheduler          // Triggers the refresh job
	cancel      context.CancelFunc // Cancels scheduler
	backoff     retry.Backoff
}

// New creates a new generic Cache and starts its refresh scheduler.
func New[T any](
	ctx context.Context,
	url string,
	mapper Mapper[T],
	opts ...Option,
) *Cache[T] {
	// Derive a cancellable context from the provided one
	// When cancel is called, all background operations will cease
	ctx, cancel := context.WithCancel(ctx)

	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	log := cfg.log.With("name", "Cache", "url", url)

	c := &Cache[T]{
		url:         url,
		mapper:      mapper,
		cancel:      cancel,
		log:         log,
		client:      cfg.client,
		minInterval: min(cfg.minInterval, cfg.maxInterval),
		maxInterval: max(cfg.minInterval, cfg.maxInterval),
		clock:       cfg.clock,
		scheduler:   cfg.scheduler,
		backoff:     cfg.backoff,
	}

	if c.client == nil {
		// The total timeout is split between the various stages of the request
		// lifecycle. The values below are somewhat arbitrary, but should
		// generally work well
		timeout := cfg.timeout

		// Keep-alives and connection pooling are disabled because requests are
		// too infrequent to benefit from them in typical use cases
		dialer := &net.Dialer{
			Timeout:   timeout / 3,
			KeepAlive: 0,
		}
		transport := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   timeout / 3,
			ResponseHeaderTimeout: timeout * 9 / 10,
			ExpectContinueTimeout: 1 * time.Second,
			DisableKeepAlives:     true,
			TLSClientConfig:       cfg.tls,
		}

		c.client = &http.Client{
			Timeout:   timeout,
			Transport: SetHeaders(transport, cfg.headers),
		}
	}

	// Use default scheduler if none provided
	if c.scheduler == nil {
		c.scheduler = NewScheduler(log)
	}

	// Resort to using constant backoff if not customized
	if c.backoff == nil {
		// Retrying at the minimum interval is effectively equivalent to not using
		// backoff at all, but it simplifies the logic in fetch
		c.backoff = retry.Constant(c.minInterval)
	}

	job := c.fetch
	go c.scheduler.Dispatch(ctx, job)
	return c
}

// fetch performs the HTTP request, parses the body, and yields the next delay.
func (c *Cache[T]) fetch(ctx context.Context) time.Duration {
	c.log.Debug("Fetching resource")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		c.log.Error("Failed to create request", "error", err)
		return c.backoff.Next()
	}

	c.mu.RLock()
	c.etag.Set(req.Header)
	c.mu.RUnlock()

	res, err := c.client.Do(req)
	if err != nil {
		if err != context.Canceled {
			c.log.Warn("HTTP request failed", "error", err)
		}
		return c.backoff.Next()
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotModified {
		c.log.Debug("ETag match, resource unchanged", "etag", c.etag)
		c.mu.Lock()
		defer c.mu.Unlock()

		c.backoff.Done()
		return c.delay(res.Header)
	}

	if res.StatusCode != http.StatusOK {
		c.log.Warn("Unsuccessful HTTP status", "status", res.Status)
		return c.backoff.Next()
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		c.log.Error("Failed to read response body", "error", err)
		return c.backoff.Next()
	}
	parsed, err := c.mapper(body)
	if err != nil {
		c.log.Error("Couldn't parse response body", "error", err)
		return c.backoff.Next()
	}

	c.mu.Lock()
	c.resource = parsed
	c.etag = NewETag(res.Header)
	c.mu.Unlock()

	c.backoff.Done()

	c.log.Info("Resource updated")
	return c.delay(res.Header)
}

// delay calculates the time to wait for the next fetch.
func (c *Cache[T]) delay(header http.Header) time.Duration {
	// Constant delay case:
	if c.minInterval == c.maxInterval {
		return c.minInterval
	}

	// Adaptive delay case:
	d := c.minInterval
	if header != nil {
		// Try Cache-Control first, since it takes precedence
		if ttl, ok := MaxAge(header); ok {
			d = ttl
		} else if expires, ok := Expires(header); ok {
			// Calculate the duration from now until the expiry time
			if ttl := expires.Sub(c.clock()); ttl > 0 {
				// Only use the duration if the expiry time lies in the future
				d = ttl
			}
		}
	}

	if d < c.minInterval {
		c.log.Debug("Clamping delay", "raw", d, "min", c.minInterval)
		return c.minInterval
	}

	if d > c.maxInterval {
		c.log.Debug("Clamping delay", "raw", d, "max", c.maxInterval)
		return c.maxInterval
	}

	return d
}

// Get returns the currently cached resource.
func (c *Cache[T]) Get() T {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.resource
}

// Stop terminates the background refresh scheduler.
func (c *Cache[T]) Stop() {
	// Logging happens inside the scheduler
	c.cancel()
}
