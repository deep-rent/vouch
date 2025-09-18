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
	DefaultMinDelay = 15 * time.Minute
	DefaultMaxDelay = 60 * time.Minute
)

// Mapper defines a function that parses a raw request payload
// into a generic type T.
type Mapper[T any] func(body []byte) (T, error)

// MaxAge extracts the 'max-age' directive from a Cache-Control header string.
func MaxAge(v string) (time.Duration, bool) {
	for p := range strings.SplitSeq(v, ",") {
		p = strings.TrimSpace(p)
		if s, ok := strings.CutPrefix(p, "max-age="); ok {
			if d, err := strconv.Atoi(s); err == nil && d > 0 {
				return time.Duration(d) * time.Second, true
			}
		}
	}
	return 0, false
}

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

// options holds all configurable parameters for a Cache.
type options struct {
	minDelay  time.Duration
	maxDelay  time.Duration
	client    *http.Client
	logger    *slog.Logger
	scheduler Scheduler
	clock     util.Clock
}

func defaults() *options {
	return &options{
		client:   http.DefaultClient,
		logger:   slog.Default(),
		minDelay: DefaultMinDelay,
		maxDelay: DefaultMaxDelay,
		clock:    util.DefaultClock,
	}
}

// Option configures the generic Cache.
type Option func(*options)

func WithMinDelay(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.minDelay = d
		}
	}
}

func WithMaxDelay(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.maxDelay = d
		}
	}
}

// WithClient provides the http.Client to use for fetching.
func WithClient(client *http.Client) Option {
	return func(o *options) {
		if client != nil {
			o.client = client
		}
	}
}

func WithTimeout(d time.Duration) Option {
	return func(o *options) {
		if d > 0 {
			o.client = &http.Client{Timeout: d}
		}
	}
}

// WithLogger provides the slog.Logger for logging.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) {
		if logger != nil {
			o.logger = logger
		}
	}
}

// WithScheduler allows injecting a custom (or mock) Scheduler.
func WithScheduler(s Scheduler) Option {
	return func(o *options) {
		if s != nil {
			o.scheduler = s
		}
	}
}

func WithClock(clock util.Clock) Option {
	return func(o *options) {
		if clock != nil {
			o.clock = clock
		}
	}
}

// Cache holds a generic, cached resource and manages its refresh cycle.
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

	o := defaults()
	for _, opt := range opts {
		opt(o)
	}

	c := &Cache[T]{
		url:       url,
		mapper:    mapper,
		cancel:    cancel,
		client:    o.client,
		logger:    o.logger,
		minDelay:  o.minDelay,
		maxDelay:  o.maxDelay,
		clock:     o.clock,
		scheduler: o.scheduler,
	}

	c.logger = c.logger.With("name", "cache.Cache", "url", c.url)

	if c.scheduler == nil {
		c.scheduler = NewScheduler(c.logger)
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

func (c *Cache[T]) Get() T {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.resource
}

// Stop terminates the background refresh scheduler.
func (c *Cache[T]) Stop() {
	// Logging happens inside the scheduler.
	c.cancel()
}
