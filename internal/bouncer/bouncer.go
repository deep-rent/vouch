package bouncer

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/cache"
	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/retry"
)

var (
	ErrMissingToken      = errors.New("missing access token")
	ErrInvalidToken      = errors.New("invalid access token")
	ErrUndefinedUserName = errors.New("undefined subject in access token")
)

type User struct {
	Name  string
	Roles []string
}

type Config struct {
	JWKS                string
	Issuers             []string
	Audiences           []string
	Leeway              time.Duration
	MaxAge              time.Duration
	UserAgent           string
	Timeout             time.Duration
	MinRefreshInterval  time.Duration
	MaxRefreshInterval  time.Duration
	AuthScheme          string
	RolesClaim          string
	BackoffMinDelay     time.Duration
	BackoffMaxDelay     time.Duration
	BackoffGrowthFactor float64
	BackoffJitterAmount float64
	Logger              *slog.Logger
}

type Bouncer struct {
	verifier   *jwt.Verifier[*jwt.DynamicClaims]
	authScheme string
	rolesClaim string
}

func New(cfg *Config) *Bouncer {
	set := jwk.NewCacheSet(
		cfg.JWKS,
		cache.WithLogger(cfg.Logger),
		cache.WithTimeout(cfg.Timeout),
		cache.WithMinInterval(cfg.MinRefreshInterval),
		cache.WithMaxInterval(cfg.MaxRefreshInterval),
		cache.WithHeader("User-Agent", cfg.UserAgent),
		cache.WithRetryOptions(
			retry.WithLogger(cfg.Logger),
			retry.WithBackoff(backoff.New(
				backoff.WithMinDelay(cfg.BackoffMinDelay),
				backoff.WithMaxDelay(cfg.BackoffMaxDelay),
				backoff.WithJitterAmount(cfg.BackoffJitterAmount),
				backoff.WithGrowthFactor(cfg.BackoffGrowthFactor),
			)),
		),
	)
	return &Bouncer{
		verifier: jwt.NewVerifier[*jwt.DynamicClaims](set).
			WithIssuers(cfg.Issuers...).
			WithAudiences(cfg.Audiences...).
			WithLeeway(cfg.Leeway).
			WithMaxAge(cfg.MaxAge),
		authScheme: cfg.AuthScheme,
		rolesClaim: cfg.RolesClaim,
	}
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
		return nil, ErrInvalidToken
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
