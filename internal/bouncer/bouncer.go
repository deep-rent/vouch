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
	ErrUndefinedUserName = errors.New("undefined subject in access token")
)

type Pass struct {
	UserName string
	Roles    []string
}

type Config struct {
	JWKS               string
	Issuers            []string
	Audiences          []string
	Leeway             time.Duration
	MaxAge             time.Duration
	UserAgent          string
	Timeout            time.Duration
	MinRefreshInterval time.Duration
	MaxRefreshInterval time.Duration
	AuthScheme         string
	RolesClaim         string
	Logger             *slog.Logger
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
				backoff.WithMinDelay(time.Second),
				backoff.WithMaxDelay(time.Minute),
				backoff.WithJitterAmount(0.66),
				backoff.WithGrowthFactor(1.75),
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

func (b *Bouncer) Bounce(req *http.Request) (*Pass, error) {
	token := header.Credentials(req.Header, b.authScheme)
	// Strip the token from the request header to prevent it from being forwarded
	// to the upstream service.
	req.Header.Del("Authorization")
	if token == "" {
		return nil, ErrMissingToken
	}
	claims, err := b.verifier.Verify([]byte(token))
	if err != nil {
		return nil, err
	}
	userName := claims.Sub
	if userName == "" {
		return nil, ErrUndefinedUserName
	}
	roles, ok := jwt.Get[[]string](claims, b.rolesClaim)
	if !ok {
		roles = make([]string, 0)
	}
	return &Pass{
		UserName: userName,
		Roles:    roles,
	}, nil
}
