package retry

import (
	"math"
	"math/rand/v2"
	"sync"
	"time"
)

const (
	DefaultExponentialMinDelay = 1 * time.Second
	DefaultExponentialMaxDelay = 1 * time.Minute
	DefaultExponentialBase     = 2.0
	DefaultJitterAmount        = 0.5
)

// Backoff defines a retry strategy.
// Implementations must be safe for concurrent use.
type Backoff interface {
	// Next returns the duration to wait before the next retry attempt.
	Next() time.Duration
	// Done resets the strategy to its initial state (e.g., after a success).
	Done()
}

// constant implements a Backoff strategy with a constant delay.
type constant struct {
	delay time.Duration
}

// Constant creates a new constant backoff strategy.
func Constant(delay time.Duration) Backoff {
	return &constant{delay: delay}
}

func (b *constant) Next() time.Duration { return b.delay }
func (b *constant) Done()               {}

// exponentialConfig holds the configuration for exponential backoff.
type exponentialConfig struct {
	minDelay time.Duration
	maxDelay time.Duration
	base     float64
}

func defaultExponentialConfig() exponentialConfig {
	return exponentialConfig{
		minDelay: DefaultExponentialMinDelay,
		maxDelay: DefaultExponentialMaxDelay,
		base:     DefaultExponentialBase,
	}
}

// ExponentialOption configures a exponential backoff.
type ExponentialOption func(*exponentialConfig)

// WithMinDelay sets the initial (base) delay for the first retry.
//
// Defaults to DefaultMinDelay if not set or non-positive.
func WithMinDelay(d time.Duration) ExponentialOption {
	return func(c *exponentialConfig) {
		if d > 0 {
			c.minDelay = d
		}
	}
}

// WithMaxDelay sets the upper bound (limit) for any retry delay.
//
// Defaults to DefaultMaxDelay if not set or non-positive.
func WithMaxDelay(d time.Duration) ExponentialOption {
	return func(c *exponentialConfig) {
		if d > 0 {
			c.maxDelay = d
		}
	}
}

// WithBase sets the base factor (multiplier) for each subsequent retry.
//
// If less than or equal to 1.0, the value is ignored and
// DefaultExponentialBase is used.
func WithBase(f float64) ExponentialOption {
	return func(c *exponentialConfig) {
		if f > 1.0 {
			c.base = f
		}
	}
}

// exponential implements the Backoff strategy with exponential increase.
type exponential struct {
	minDelay float64
	maxDelay float64
	factor   float64
	mu       sync.Mutex
	attempts int
}

// Exponential creates a new exponential backoff strategy.
func Exponential(opts ...ExponentialOption) Backoff {
	cfg := defaultExponentialConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	cfg.maxDelay = max(cfg.maxDelay, cfg.minDelay)
	return &exponential{
		minDelay: float64(cfg.minDelay),
		maxDelay: float64(cfg.maxDelay),
		factor:   cfg.base,
	}
}

// Next calculates the next backoff duration.
func (b *exponential) Next() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	d := b.minDelay * math.Pow(b.factor, float64(b.attempts))
	b.attempts++
	return time.Duration(min(d, b.maxDelay))
}

// Done resets the attempt counter.
func (b *exponential) Done() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attempts = 0
}

// Rand is a minimal facade for rand.Rand.
type Rand interface {
	// Float64 returns a pseudo-random number in [0.0, 1.0).
	Float64() float64
}

type jitterConfig struct {
	p float64
	r Rand
}

func defaultJitterConfig() jitterConfig {
	return jitterConfig{
		p: DefaultJitterAmount,
		r: seed(),
	}
}

type JitterOption func(*jitterConfig)

func WithAmount(p float64) JitterOption {
	return func(c *jitterConfig) {
		c.p = min(1.0, p)
	}
}

func WithRand(r Rand) JitterOption {
	return func(c *jitterConfig) {
		if r != nil {
			c.r = r
		}
	}
}

type jitter struct {
	wrapped Backoff
	p       float64
	mu      sync.Mutex // guards r
	r       Rand
}

// Jitter wraps a Backoff strategy and adds randomized jitter.
//
// The jitter argument is a percentage (0.0 to 1.0) that defines the
// randomization window. The returned duration will be a random value between
// [ (1.0 - jitter) * delay, delay ].
//
// For example, 0.5 (50%) jitter on a 10s delay will return a random value
// in the [5s, 10s] range.
//
// If r is nil, a default, thread-safe rand.Rand is created.

func Jitter(b Backoff, opts ...JitterOption) Backoff {
	cfg := defaultJitterConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.p <= 0.0 {
		return b // No jitter requested
	}

	return &jitter{
		wrapped: b,
		p:       cfg.p,
		r:       cfg.r,
	}
}

// Next calculates the wrapped backoff's next delay, then applies jitter.
func (j *jitter) Next() time.Duration {
	d := float64(j.wrapped.Next())

	j.mu.Lock()
	r := j.r.Float64()
	j.mu.Unlock()

	return time.Duration(d * (1.0 - r*j.p))
}

// Done resets the wrapped backoff strategy.
func (j *jitter) Done() {
	j.wrapped.Done()
}

// seed creates a new random number generator seeded with the current time.
func seed() Rand {
	s1 := uint64(time.Now().UnixNano())
	s2 := s1 + 1
	return rand.New(rand.NewPCG(s1, s2))
}
