package bouncer

import (
	"errors"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/backoff"
	"github.com/deep-rent/nexus/cache"
	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/retry"
	"github.com/deep-rent/vouch/internal/config"
)

var ErrMissingToken = errors.New("missing access token")
var ErrUndefinedSubject = errors.New("undefined subject in access token")

type Pass struct {
	User  string
	Roles []string
}

type Bouncer struct {
	verifier   *jwt.Verifier[*jwt.DynamicClaims]
	authScheme string
	rolesClaim string
}

func New(cfg *config.Config) *Bouncer {
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
	if token == "" {
		return nil, ErrMissingToken
	}
	claims, err := b.verifier.Verify([]byte(token))
	if err != nil {
		return nil, err
	}
	user := claims.Sub
	if user == "" {
		return nil, ErrUndefinedSubject
	}
	roles, ok := jwt.Get[[]string](claims, b.rolesClaim)
	if !ok {
		roles = make([]string, 0)
	}
	return &Pass{
		User:  user,
		Roles: roles,
	}, nil
}
