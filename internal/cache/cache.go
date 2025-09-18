package cache

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deep-rent/vouch/internal/util"
)

const (
	// DefaultMinDelay is the default minimum delay between fetches.
	DefaultMinDelay = 15 * time.Minute
	// DefaultMaxDelay is the default maximum delay between fetches.
	DefaultMaxDelay = 60 * time.Minute
)

// Mapper defines a function that parses a raw request payload
// into a generic type T.
type Mapper[T any] func(body []byte) (T, error)

// config holds all configurable parameters for a Cache.
type config struct {
	minDelay  time.Duration
	maxDelay  time.Duration
	client    *http.Client
	logger    *slog.Logger
	scheduler Scheduler
	clock     util.Clock
}

// defaultConfig initializes a configuration object with default settings.
func defaultConfig() *config {
	return &config{
		client:   http.DefaultClient,
		logger:   slog.Default(),
		minDelay: DefaultMinDelay,
		maxDelay: DefaultMaxDelay,
		clock:    util.DefaultClock,
	}
}

// Option defines a function for setting cache options.
type Option func(*config)

// WithMinDelay sets the minimum delay between fetches.
//
// Non-positive values are ignored, and DefaultMinDelay is used.
func WithMinDelay(d time.Duration) Option {
	return func(o *config) {
		if d > 0 {
			o.minDelay = d
		}
	}
}

// WithMinDelay sets the minimum delay between fetches.
//
// Non-positive values are ignored, and DefaultMaxDelay is used.
func WithMaxDelay(d time.Duration) Option {
	return func(o *config) {
		if d > 0 {
			o.maxDelay = d
		}
	}
}

// WithClient provides the http.Client to use for fetching.
func WithClient(client *http.Client) Option {
	return func(o *config) {
		if client != nil {
			o.client = client
		}
	}
}

// WithTimeout sets the request timeout for the internal HTTP client.
//
// Negative values are ignored. Zero means no timeout (not recommended).
func WithTimeout(d time.Duration) Option {
	return func(o *config) {
		if d < 0 {
			o.client.Timeout = d
		}
	}
}

// WithTransport specifies the mechanism by which individual HTTP requests
// are made.
//
// If nil is given, this option is ignored. The default transport is empty.
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
// It periodically fetches the resource from a given URL, using HTTP caching
// headers to minimize data transfer. The resource is parsed through a user-
// provided Mapper function and can be accessed via Get. All methods are safe
// for concurrent use.
type Cache[T any] struct {
	url          string
	client       *http.Client
	logger       *slog.Logger
	mapper       Mapper[T]
	clock        util.Clock
	minDelay     time.Duration
	maxDelay     time.Duration
	mu           sync.RWMutex
	resource     T
	etag         string
	lastModified string
	scheduler    Scheduler
	cancel       context.CancelFunc
}

// New creates a new generic Cache and starts its refresh scheduler.
func New[T any](
	ctx context.Context,
	url string,
	mapper Mapper[T],
	opts ...Option,
) *Cache[T] {
	ctx, cancel := context.WithCancel(ctx)

	cfg := defaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	logger := cfg.logger.With("name", "Cache", "url", url)

	c := &Cache[T]{
		url:       url,
		mapper:    mapper,
		cancel:    cancel,
		logger:    logger,
		client:    cfg.client,
		minDelay:  cfg.minDelay,
		maxDelay:  cfg.maxDelay,
		clock:     cfg.clock,
		scheduler: cfg.scheduler,
	}

	if c.scheduler == nil {
		c.scheduler = NewScheduler(logger)
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
		return c.retry()
	}

	c.mu.RLock()
	if c.etag != "" {
		req.Header.Set("If-None-Match", c.etag)
	}
	if c.lastModified != "" {
		req.Header.Set("If-Modified-Since", c.lastModified)
	}
	c.mu.RUnlock()

	res, err := c.client.Do(req)
	if err != nil {
		if err != context.Canceled {
			c.logger.Warn("HTTP request failed", "error", err)
		}
		return c.retry()
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusNotModified {
		c.logger.Debug("ETag match, resource unchanged", "etag", c.etag)
		c.mu.Lock()
		defer c.mu.Unlock()

		return c.delay(res.Header)
	}

	if res.StatusCode != http.StatusOK {
		c.logger.Warn("Unsuccessful HTTP status", "status", res.Status)
		return c.retry()
	}

	body, err := io.ReadAll(res.Body)
	if err != nil {
		c.logger.Error("Failed to read response body", "error", err)
		return c.retry()
	}
	parsed, err := c.mapper(body)
	if err != nil {
		c.logger.Error("Couldn't parse response body", "error", err)
		return c.retry()
	}

	c.mu.Lock()
	c.resource = parsed
	c.etag = res.Header.Get("ETag")
	c.lastModified = res.Header.Get("Last-Modified")
	c.mu.Unlock()

	c.logger.Info("Resource updated")
	return c.delay(res.Header)
}

// retry returns the delay to use after a failed fetch attempt.
func (c *Cache[T]) retry() time.Duration {
	return c.delay(nil)
}

// delay calculates the time to wait for the next fetch.
func (c *Cache[T]) delay(header http.Header) time.Duration {
	// Constant delay
	if c.minDelay == c.maxDelay {
		return c.minDelay
	}

	// Adaptive delay
	duration := c.minDelay
	if header != nil {
		// Try Cache-Control first, as it takes precedence.
		if d, ok := MaxAge(header.Get("Cache-Control")); ok {
			duration = d
		} else if t, ok := Expires(header.Get("Expires")); ok {
			// Calculate the duration from now until the expiry time.
			if d := t.Sub(c.clock()); d > 0 {
				// Only use the duration if the expiry time is in the future.
				duration = d
			}
		}
	}

	if duration < c.minDelay {
		c.logger.Debug("Clamping delay", "raw", duration, "min", c.minDelay)
		return c.minDelay
	}

	if duration > c.maxDelay {
		c.logger.Debug("Clamping delay", "raw", duration, "max", c.maxDelay)
		return c.maxDelay
	}

	return duration
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

// MaxAge extracts the 'max-age' directive from a Cache-Control header string.
// If valid, it returns the duration and true, false otherwise.
func MaxAge(v string) (time.Duration, bool) {
	if v != "" {
		for p := range strings.SplitSeq(v, ",") {
			p = strings.TrimSpace(p)
			if s, ok := strings.CutPrefix(p, "max-age="); ok {
				if d, err := strconv.Atoi(s); err == nil && d > 0 {
					return time.Duration(d) * time.Second, true
				}
			}
		}
	}
	return 0, false
}

// Expires parses an HTTP Expires header value.
// If valid, it returns the timestamp and true, false otherwise.
func Expires(v string) (time.Time, bool) {
	if v == "" {
		return time.Time{}, false
	}
	t, err := http.ParseTime(v)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
