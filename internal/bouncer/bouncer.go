// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package bouncer provides the logic for verifying JWTs against a remote JWKS.
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

// User represents an authenticated CouchDB user.
// This data gets forwarded via proxy authentication headers.
type User struct {
	Name  string   // CouchDB username, taken from the "sub" claim.
	Roles []string // List of CouchDB roles, read from a configurable claim.
}

// Config holds the configuration for the Bouncer.
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

// Bouncer is responsible for validating incoming HTTP requests by verifying
// their bearer tokens.
type Bouncer struct {
	verifier   *jwt.Verifier[*jwt.DynamicClaims]
	authScheme string
	rolesClaim string
	tick       scheduler.Tick
}

// New creates a new Bouncer instance.
func New(cfg *Config) *Bouncer {
	// Create a caching JWK set that automatically refreshes keys from the
	// remote endpoint.
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
		// Configure the JWT verifier with the key set and validation rules.
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

// Start begins the background process for refreshing the JWK set.
// It blocks until the context is canceled.
func (b *Bouncer) Start(ctx context.Context) error {
	sched := scheduler.New(ctx)
	sched.Dispatch(b.tick)

	<-ctx.Done()
	sched.Shutdown()
	return nil
}

// Bounce verifies the bearer token in the request and returns the authenticated
// user. It returns an error if the token is missing, invalid, or expired.
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
	// Extract roles from the custom claim.
	roles, ok := jwt.Get[[]string](claims, b.rolesClaim)
	if !ok {
		roles = make([]string, 0)
	}
	return &User{
		Name:  name,
		Roles: roles,
	}, nil
}
