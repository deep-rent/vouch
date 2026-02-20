package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/deep-rent/nexus/cache"
	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/scheduler"
	"github.com/deep-rent/vouch/internal/config"
)

var ErrMissingCredentials = errors.New("missing credentials")

// Claims represents the JWT claims, including standard and dynamic claims.
type Claims struct {
	jwt.DynamicClaims
}

// Authenticator provides JWT authentication capabilities.
type Authenticator struct {
	verifier *jwt.Verifier[*Claims]
	keySet   jwk.CacheSet
}

// New creates a new Authenticator.
func New(cfg *config.Config) *Authenticator {
	keySet := jwk.NewCacheSet(
		cfg.JWKSURL.String(),
		cache.WithMinInterval(5*time.Minute),
		cache.WithTimeout(cfg.JWKSFetchTimeout),
	)

	// Start a scheduler to refresh the key set in the background.
	sched := scheduler.New(context.Background())
	sched.Dispatch(keySet)

	return &Authenticator{
		verifier: jwt.NewVerifier[*Claims](keySet),
		keySet:   keySet,
	}
}

// Authenticate validates the JWT from the request and returns the claims.
func (a *Authenticator) Authenticate(r *http.Request) (*Claims, error) {
	// Extract the token from the "Authorization" header.
	token := header.Credentials(r.Header, "Bearer")
	if token == "" {
		return nil, ErrMissingCredentials
	}

	// Validate the token.
	claims, err := a.verifier.Verify([]byte(token))
	if err != nil {
		return nil, err
	}

	return claims, nil
}
