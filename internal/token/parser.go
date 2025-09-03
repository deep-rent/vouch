package token

import (
	"context"
	"net/http"
	"strings"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/key"
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
	keys key.Store
	opts []jwt.ParseOption
}

func NewParser(ctx context.Context, cfg config.Token) (*Parser, error) {
	keys, err := key.NewStore(ctx, cfg.Keys)
	if err != nil {
		return nil, err
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
	n := len(scheme)
	if n > len(auth) || !strings.EqualFold(auth[:n], scheme) {
		return nil, ErrMissingToken
	}
	s := strings.TrimSpace(auth[n:])
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

func (p *Parser) parse(
	ctx context.Context, set jwk.Set, s string,
) (jwt.Token, error) {
	opts := make([]jwt.ParseOption, 0, len(p.opts)+2)
	opts = append(opts, jwt.WithKeySet(set), jwt.WithContext(ctx))
	opts = append(opts, p.opts...)

	return jwt.ParseString(s, opts...)
}
