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

type TokenConfig struct {
	Issuers    []string
	Audiences  []string
	Leeway     time.Duration
	MaxAge     time.Duration
	AuthScheme string
	RolesClaim string
}

type KeysConfig struct {
	URL                 string
	UserAgent           string
	Timeout             time.Duration
	MinRefreshInterval  time.Duration
	MaxRefreshInterval  time.Duration
	BackoffMinDelay     time.Duration
	BackoffMaxDelay     time.Duration
	BackoffGrowthFactor float64
	BackoffJitterAmount float64
}

type Config struct {
	Token  *TokenConfig
	Keys   *KeysConfig
	Logger *slog.Logger
}

type Bouncer struct {
	verifier   *jwt.Verifier[*jwt.DynamicClaims]
	authScheme string
	rolesClaim string
	logger     *slog.Logger
}

func New(cfg *Config) *Bouncer {
	set := jwk.NewCacheSet(
		cfg.Keys.URL,
		cache.WithLogger(cfg.Logger),
		cache.WithTimeout(cfg.Keys.Timeout),
		cache.WithMinInterval(cfg.Keys.MinRefreshInterval),
		cache.WithMaxInterval(cfg.Keys.MaxRefreshInterval),
		cache.WithHeader("User-Agent", cfg.Keys.UserAgent),
		cache.WithRetryOptions(
			retry.WithLogger(cfg.Logger),
			retry.WithBackoff(backoff.New(
				backoff.WithMinDelay(cfg.Keys.BackoffMinDelay),
				backoff.WithMaxDelay(cfg.Keys.BackoffMaxDelay),
				backoff.WithJitterAmount(cfg.Keys.BackoffJitterAmount),
				backoff.WithGrowthFactor(cfg.Keys.BackoffGrowthFactor),
			)),
		),
	)
	return &Bouncer{
		verifier: jwt.NewVerifier[*jwt.DynamicClaims](set).
			WithIssuers(cfg.Token.Issuers...).
			WithAudiences(cfg.Token.Audiences...).
			WithLeeway(cfg.Token.Leeway).
			WithMaxAge(cfg.Token.MaxAge),
		authScheme: cfg.Token.AuthScheme,
		rolesClaim: cfg.Token.RolesClaim,
		logger:     cfg.Logger,
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
		b.logger.DebugContext(
			req.Context(),
			"Token verification failed",
			slog.String("token", token), slog.Any("error", err),
		)
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
