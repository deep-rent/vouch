package bouncer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/cache"
	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/retry"
	"github.com/deep-rent/nexus/scheduler"
)

var (
	ErrMissingToken      = errors.New("missing access token")
	ErrUndefinedUserName = errors.New("undefined subject in access token")
)

type User struct {
	Name  string
	Roles []string
}

type Config struct {
	TokenIssuers            []string
	TokenAudiences          []string
	TokenLeeway             time.Duration
	TokenMaxAge             time.Duration
	TokenAuthScheme         string
	TokenRolesClaim         string
	KeysURL                 string
	KeysUserAgent           string
	KeysTimeout             time.Duration
	KeysMinRefreshInterval  time.Duration
	KeysMaxRefreshInterval  time.Duration
	KeysAttemptLimit        int
	KeysBackoffMinDelay     time.Duration
	KeysBackoffMaxDelay     time.Duration
	KeysBackoffGrowthFactor float64
	KeysBackoffJitterAmount float64
	Logger                  *slog.Logger
}

type Bouncer struct {
	verifier   *jwt.Verifier[*jwt.DynamicClaims]
	authScheme string
	rolesClaim string
	tick       scheduler.Tick
}

func New(cfg *Config) *Bouncer {
	set := jwk.NewCacheSet(
		cfg.KeysURL,
		cache.WithLogger(cfg.Logger),
		cache.WithTimeout(cfg.KeysTimeout),
		cache.WithMinInterval(cfg.KeysMinRefreshInterval),
		cache.WithMaxInterval(cfg.KeysMaxRefreshInterval),
		cache.WithHeader("User-Agent", cfg.KeysUserAgent),
		cache.WithRetryOptions(
			retry.WithLogger(cfg.Logger),
			retry.WithAttemptLimit(cfg.KeysAttemptLimit),
			retry.WithBackoff(backoff.New(
				backoff.WithMinDelay(cfg.KeysBackoffMinDelay),
				backoff.WithMaxDelay(cfg.KeysBackoffMaxDelay),
				backoff.WithJitterAmount(cfg.KeysBackoffJitterAmount),
				backoff.WithGrowthFactor(cfg.KeysBackoffGrowthFactor),
			)),
		),
	)
	return &Bouncer{
		verifier: jwt.NewVerifier[*jwt.DynamicClaims](set).
			WithIssuers(cfg.TokenIssuers...).
			WithAudiences(cfg.TokenAudiences...).
			WithLeeway(cfg.TokenLeeway).
			WithMaxAge(cfg.TokenMaxAge),
		authScheme: cfg.TokenAuthScheme,
		rolesClaim: cfg.TokenRolesClaim,
		tick:       set,
	}
}

func (b *Bouncer) Start(ctx context.Context) error {
	sched := scheduler.New(ctx)
	sched.Dispatch(b.tick)

	<-ctx.Done()
	sched.Shutdown()
	return nil
}

func (b *Bouncer) Bounce(req *http.Request) (*User, error) {
	token := header.Credentials(req.Header, b.authScheme)
	// Strip the token from the request header to prevent it from being forwarded
	// to the upstream service.
	req.Header.Del("Authorization")
	if token == "" {
		return nil, ErrMissingToken
	}
	claims, err := b.verifier.Verify([]byte(token))
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}
	name := claims.Sub
	if name == "" {
		return nil, ErrUndefinedUserName
	}
	roles, ok := jwt.Get[[]string](claims, b.rolesClaim)
	if !ok {
		roles = make([]string, 0)
	}
	return &User{
		Name:  name,
		Roles: roles,
	}, nil
}
