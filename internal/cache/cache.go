package cache

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/deep-rent/vouch/internal/retry"
	"github.com/deep-rent/vouch/internal/util"
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
	client      *http.Client
	logger      *slog.Logger
	backoff     retry.Backoff
	scheduler   Scheduler
	clock       util.Clock
}

// defaultConfig initializes a configuration object with default settings.
func defaultConfig() config {
	return config{
		client:      &http.Client{Timeout: DefaultTimeout},
		logger:      slog.Default(),
		minInterval: DefaultMinInterval,
		maxInterval: DefaultMaxInterval,
		clock:       util.DefaultClock,
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
	return func(o *config) {
		if d > 0 {
			o.minInterval = d
		}
	}
}

// WithMaxInterval sets the maximum time to wait between fetches.
//
// Non-positive values are ignored, and DefaultMaxInterval is used. The value
// will be bounded below by the minimum interval at configuration time. If
// both are equal, the cache will be refreshed at a constant rate.
func WithMaxInterval(d time.Duration) Option {
	return func(o *config) {
		if d > 0 {
			o.maxInterval = d
		}
	}
}

// WithClient provides the http.Client to use for fetching.
//
// If nil is given, this option is ignored. Setting a custom client overrides
// previous timeout and transport settings.
func WithClient(client *http.Client) Option {
	return func(o *config) {
		if client != nil {
			o.client = client
		}
	}
}

// WithTimeout sets the request timeout for the internal HTTP client.
//
// Non-positive values are ignored, and DefaultTimeout is used. Note that zero
// values are not allowed, as they disable timeouts entirely, which makes
// the client vulnerable to hanging requests.
func WithTimeout(d time.Duration) Option {
	return func(o *config) {
		if d > 0 {
			o.client.Timeout = d
		}
	}
}

// WithTransport specifies the mechanism by which individual HTTP requests
// are made.
//
// If nil is given, this option is ignored. The default client uses
// http.DefaultTransport, which is usually sufficient.
func WithTransport(t http.RoundTripper) Option {
	return func(o *config) {
		if t != nil {
			o.client.Transport = t
		}
	}
}

// WithLogger provides a custom logger for the cache.
//
// If nil is given, this option is ignored. By default, slog.Default() is used.
func WithLogger(logger *slog.Logger) Option {
	return func(o *config) {
		if logger != nil {
			o.logger = logger
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
	return func(o *config) {
		if b != nil {
			o.backoff = b
		}
	}
}

// WithScheduler allows injecting a custom scheduler.
//
// This option should only be overridden for testing.
func WithScheduler(s Scheduler) Option {
	return func(o *config) {
		if s != nil {
			o.scheduler = s
		}
	}
}

// WithClock allows injecting a custom time provider.
//
// This option should only be overridden for testing.
func WithClock(clock util.Clock) Option {
	return func(o *config) {
		if clock != nil {
			o.clock = clock
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
	logger      *slog.Logger
	mapper      Mapper[T]
	clock       util.Clock
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

	logger := cfg.logger.With("name", "Cache", "url", url)

	c := &Cache[T]{
		url:         url,
		mapper:      mapper,
		cancel:      cancel,
		logger:      logger,
		client:      cfg.client,
		minInterval: min(cfg.minInterval, cfg.maxInterval),
		maxInterval: max(cfg.minInterval, cfg.maxInterval),
		clock:       cfg.clock,
		scheduler:   cfg.scheduler,
		backoff:     cfg.backoff,
	}

	// Use default scheduler if none provided
	if c.scheduler == nil {
		c.scheduler = NewScheduler(logger)
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

// fetch performs the HTTP request, parses the body, and returns the next delay.
func (c *Cache[T]) fetch(ctx context.Context) time.Duration {
	c.logger.Debug("Fetching resource")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		c.logger.Error("Failed to create request", "error", err)
		return c.backoff.Next()
	}

	c.mu.RLock()
	c.etag.Set(req.Header)
	c.mu.RUnlock()

	res, err := c.client.Do(req)
	if err != nil {
		if err != context.Canceled {
			c.logger.Warn("HTTP request failed", "error", err)
		}
		return c.backoff.Next()
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotModified {
		c.logger.Debug("ETag match, resource unchanged", "etag", c.etag)
		c.mu.Lock()
		defer c.mu.Unlock()

		c.backoff.Done()
		return c.delay(res.Header)
	}

	if res.StatusCode != http.StatusOK {
		c.logger.Warn("Unsuccessful HTTP status", "status", res.Status)
		return c.backoff.Next()
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		c.logger.Error("Failed to read response body", "error", err)
		return c.backoff.Next()
	}
	parsed, err := c.mapper(body)
	if err != nil {
		c.logger.Error("Couldn't parse response body", "error", err)
		return c.backoff.Next()
	}

	c.mu.Lock()
	c.resource = parsed
	c.etag = NewETag(res.Header)
	c.mu.Unlock()

	c.backoff.Done()

	c.logger.Info("Resource updated")
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
		c.logger.Debug("Clamping delay", "raw", d, "min", c.minInterval)
		return c.minInterval
	}

	if d > c.maxInterval {
		c.logger.Debug("Clamping delay", "raw", d, "max", c.maxInterval)
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
