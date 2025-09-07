// Copyright (c) 2025-present deep.rent GmbH (https://www.deep.rent)
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

package token

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/key"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Header is the HTTP header used to transmit the Bearer token.
const Header = "Authorization"

// AuthenticationError represents an authentication failure that should be
// surfaced to the client with a WWW-Authenticate challenge as per RFC 6750.
type AuthenticationError struct {
	msg string // human-readable error text
	// Challenge is the value to include in the WWW-Authenticate header.
	Challenge string
}

// Error implements the error interface.
func (e *AuthenticationError) Error() string {
	return e.msg
}

// scheme is the case-insensitive HTTP Authorization scheme prefix we expect.
const scheme = "Bearer "

// ErrMissingToken signals that the Authorization header is missing,
// malformed, or uses the wrong scheme.
var ErrMissingToken = &AuthenticationError{
	msg:       "missing access token",
	Challenge: scheme + `error="invalid_request"`,
}

// ErrInvalidToken indicates that the access token could not be parsed or
// failed validation (signature, expiration, issuer/audience, etc.).
var ErrInvalidToken = &AuthenticationError{
	msg:       "invalid access token",
	Challenge: scheme + `error="invalid_token"`,
}

// Parser extracts and validates Bearer tokens from HTTP requests.
// It obtains verification keys from the provided key.Provider and applies
// optional verification constraints derived from config.Token.
type Parser interface {
	// Parse extracts a Bearer token from the request's Authorization header and
	// validates it using the current JWKS and configured constraints.
	// Returns:
	//   - ErrMissingToken when the header is absent, malformed, or uses a
	//     different scheme.
	//   - ErrInvalidToken when parsing/validation fails.
	//   - Other errors may be returned from the key provider lookup.
	Parse(req *http.Request) (jwt.Token, error)
}

// ParserFunc is an adapter to allow the use of ordinary functions as Parsers.
type ParserFunc func(req *http.Request) (jwt.Token, error)

// Parse implements the Parser interface.
func (f ParserFunc) Parse(req *http.Request) (jwt.Token, error) {
	return f(req)
}

// parser is the default Parser implementation.
type parser struct {
	keys key.Provider      // JWK provider used for signature verification
	opts []jwt.ParseOption // additional parsing/validation options
}

// Parse extracts a Bearer token from req's Authorization header and validates
// it using the current JWKS and configured constraints.
// Returns:
//   - ErrMissingToken when the header is absent, malformed, or uses a
//     different scheme.
//   - ErrInvalidToken when parsing/validation fails.
//   - Other errors may be returned from the key provider lookup.
func (p *parser) Parse(req *http.Request) (jwt.Token, error) {
	raw := bearer(req.Header.Get(Header))
	if raw == "" {
		return nil, ErrMissingToken
	}
	ctx := req.Context()
	set, err := p.keys.Keys(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := p.parse(ctx, set, raw)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return tok, nil
}

// parse is an internal helper that applies the provided key set and
// context, plus the parser's configured options, to parse and
// validate the token string.
func (p *parser) parse(
	ctx context.Context, set jwk.Set, s string,
) (jwt.Token, error) {
	opts := make([]jwt.ParseOption, 0, len(p.opts)+2)
	opts = append(opts, jwt.WithKeySet(set), jwt.WithContext(ctx))
	opts = append(opts, p.opts...)

	return jwt.ParseString(s, opts...)
}

// Ensure parser satisfies the Parser contract.
var _ Parser = (*parser)(nil)

// NewParser constructs a Parser configured from the configuration.
// It prepares validation options (leeway, issuer, audience, clock) and
// builds a key provider to retrieve the JWKS used for verification.
func NewParser(ctx context.Context, cfg config.Token) (Parser, error) {
	keys, err := key.NewProvider(ctx, cfg.Keys)
	if err != nil {
		return nil, fmt.Errorf("create key provider: %w", err)
	}
	opts := make([]jwt.ParseOption, 0, 4)
	if v := cfg.Leeway; v != 0 {
		opts = append(opts, jwt.WithAcceptableSkew(v))
	}
	if v := strings.TrimSpace(cfg.Issuer); v != "" {
		opts = append(opts, jwt.WithIssuer(v))
	}
	if v := strings.TrimSpace(cfg.Audience); v != "" {
		opts = append(opts, jwt.WithAudience(v))
	}
	if v := cfg.Clock; v != nil {
		opts = append(opts, jwt.WithClock(v))
	}
	return &parser{
		keys: keys,
		opts: opts,
	}, nil
}

// bearer extracts the token from the Authorization header value.
func bearer(auth string) string {
	auth = strings.TrimSpace(auth)
	if len(scheme) > len(auth) || !strings.EqualFold(auth[:len(scheme)], scheme) {
		return ""
	}
	return strings.TrimSpace(auth[len(scheme):])
}
