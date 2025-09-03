package token

import (
	"context"
	"net/http"
	"strings"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/keys"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

type AuthenticationError struct {
	message   string
	Challenge string
}

func (e *AuthenticationError) Error() string {
	return e.message
}

const scheme = "Bearer "

var ErrMissingToken = &AuthenticationError{
	message:   "missing access token",
	Challenge: scheme + `error="invalid_request"`,
}

var ErrInvalidToken = &AuthenticationError{
	message:   "invalid access token",
	Challenge: scheme + `error="invalid_token"`,
}

type Parser struct {
	keys keys.Store
	opts []jwt.ParseOption
}

func NewParser(cfg config.Token) (*Parser, error) {
	keys, err := keys.NewStore(cfg.Keys)
	if err != nil {
		return nil, err
	}
	opts := make([]jwt.ParseOption, 0, 4)
	if lee := cfg.Leeway; lee != 0 {
		opts = append(opts, jwt.WithAcceptableSkew(lee))
	}
	if iss := strings.TrimSpace(cfg.Issuer); iss != "" {
		opts = append(opts, jwt.WithIssuer(iss))
	}
	if aud := strings.TrimSpace(cfg.Audience); aud != "" {
		opts = append(opts, jwt.WithAudience(aud))
	}
	if clk := cfg.Clock; clk != nil {
		opts = append(opts, jwt.WithClock(clk))
	}
	return &Parser{
		keys: keys,
		opts: opts,
	}, nil
}

func (p *Parser) Parse(req *http.Request) (jwt.Token, error) {
	auth := strings.TrimSpace(req.Header.Get("Authorization"))
	if auth == "" {
		return nil, ErrMissingToken
	}
	if len(auth) < len(scheme) || !strings.EqualFold(auth[:len(scheme)], scheme) {
		return nil, ErrMissingToken
	}
	s := strings.TrimSpace(auth[len(scheme):])
	if s == "" {
		return nil, ErrMissingToken
	}
	ctx := req.Context()
	set, err := p.keys.Keys(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := p.parse(ctx, set, s)
	if err != nil {
		return nil, ErrInvalidToken
	}
	return tok, nil
}

func (p *Parser) parse(ctx context.Context, set jwk.Set, s string) (jwt.Token, error) {
	opts := make([]jwt.ParseOption, 0, len(p.opts)+2)
	opts = append(opts, jwt.WithKeySet(set), jwt.WithContext(ctx))
	opts = append(opts, p.opts...)

	return jwt.ParseString(s, opts...)
}
