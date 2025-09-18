package retry

import (
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultMinDelay is the default minimum delay for exponential backoff.
	DefaultMinDelay = 1 * time.Second
	// DefaultMaxDelay is the default maximum delay for exponential backoff.
	DefaultMaxDelay = 1 * time.Minute
	// DefaultFactor is the default base factor for exponential backoff.
	DefaultFactor = 2.0
	// DefaultJitter is the default jitter amount.
	DefaultJitter = 0.5
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
//
// The delay must be positive, or this function panics.
func Constant(delay time.Duration) Backoff {
	if delay <= 0 {
		panic("delay is non-positive")
	}

	return &constant{delay: delay}
}

func (b *constant) Next() time.Duration { return b.delay }
func (b *constant) Done()               {}

// exponentialConfig holds the configuration for exponential backoff.
type exponentialConfig struct {
	minDelay time.Duration
	maxDelay time.Duration
	factor   float64
}

// defaultExponentialConfig initializes a configuration object with defaults.
func defaultExponentialConfig() exponentialConfig {
	return exponentialConfig{
		minDelay: DefaultMinDelay,
		maxDelay: DefaultMaxDelay,
		factor:   DefaultFactor,
	}
}

// ExponentialOption configures an exponential backoff strategy.
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

// WithFactor sets the base factor (multiplier) for each subsequent retry.
//
// If less than or equal to 1.0, the value is ignored and DefaultFactor is used.
func WithFactor(f float64) ExponentialOption {
	return func(c *exponentialConfig) {
		if f > 1.0 {
			c.factor = f
		}
	}
}

// exponential implements the Backoff strategy with exponential increase.
type exponential struct {
	minDelay time.Duration
	maxDelay time.Duration
	factor   float64
	attempts atomic.Int64
}

// Exponential creates a new exponential backoff strategy.
//
// The delay increases exponentially with each call to Next, starting from the
// minimum delay and up to the maximum delay. The attempt counter is reset by
// calling Done. Growth is controlled by the base factor.
func Exponential(opts ...ExponentialOption) Backoff {
	cfg := defaultExponentialConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	cfg.maxDelay = max(cfg.maxDelay, cfg.minDelay)
	return &exponential{
		minDelay: cfg.minDelay,
		maxDelay: cfg.maxDelay,
		factor:   cfg.factor,
		// attempts is zero-initialized
	}
}

// Next calculates the next backoff duration.
func (b *exponential) Next() time.Duration {
	a := b.attempts.Load()
	d := time.Duration(float64(b.minDelay) * math.Pow(b.factor, float64(a)))

	if d < b.maxDelay {
		b.attempts.Add(1)
		return d
	}

	return b.maxDelay
}

// Done resets the attempt counter.
func (b *exponential) Done() {
	b.attempts.Store(0)
}

// Rand is a minimal facade for rand.Rand.
type Rand interface {
	// Float64 returns a pseudo-random number in [0.0, 1.0).
	Float64() float64
}

// jitterConfig holds the configuration for jitter.
type jitterConfig struct {
	p float64
	r Rand
}

// defaultJitterConfig initializes a configuration object with defaults.
func defaultJitterConfig() jitterConfig {
	return jitterConfig{
		p: DefaultJitter,
		r: nil, // lazy init
	}
}

// JitterOption configures the jitter wrapper.
type JitterOption func(*jitterConfig)

// WithAmount sets the amount of jitter as a percentage.
//
// The value is clamped to at most 1.0 (full jitter). If non-positive, no
// jitter is applied.
func WithAmount(p float64) JitterOption {
	return func(c *jitterConfig) {
		c.p = min(1.0, p)
	}
}

// WithRand sets a custom random number generator.
//
// If nil is given, this option is ignored and a default generator is used.
func WithRand(r Rand) JitterOption {
	return func(c *jitterConfig) {
		if r != nil {
			c.r = r
		}
	}
}

// jitter decorates a Backoff strategy with random jitter.
type jitter struct {
	wrapped Backoff
	p       float64
	mu      sync.Mutex // guards r
	r       Rand
}

// Jitter wraps a Backoff strategy to employ randomized jitter, spreading
// out retry attempts in time. The jitter percentage determines the maximum
// reduction applied to the current delay.
func Jitter(b Backoff, opts ...JitterOption) Backoff {
	cfg := defaultJitterConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.p <= 0.0 {
		return b // No jitter requested
	}
	if cfg.r == nil {
		cfg.r = seed()
	}
	return &jitter{
		wrapped: b,
		p:       cfg.p,
		r:       cfg.r,
	}
}

// Next calculates the wrapped backoff's next delay, then incorporates jitter.
func (j *jitter) Next() time.Duration {
	d := float64(j.wrapped.Next())

	j.mu.Lock()
	r := j.r.Float64()
	j.mu.Unlock()

	return time.Duration(d * (1.0 - r*j.p))
}

// Done delegates to the wrapped backoff strategy.
func (j *jitter) Done() {
	j.wrapped.Done()
}

// seed creates a new random number generator seeded with the current time.
func seed() Rand {
	s1 := uint64(time.Now().UnixNano())
	s2 := s1 + 1
	return rand.New(rand.NewPCG(s1, s2))
}
