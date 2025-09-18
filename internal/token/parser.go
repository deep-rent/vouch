package token

import (
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/deep-rent/vouch/internal/util"
)

type Parser interface {
	Parse(req *http.Request) (Claims, error)
}

func NewParser(opts ...ParserOption) Parser {
	cfg := &[]jwt.ParseOption{
		jwt.WithValidate(true),
		jwt.WithPedantic(true),
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return &parser{opts: *cfg}
}

type parserConfig *[]jwt.ParseOption

type ParserOption func(parserConfig)

func WithAudience(aud string) ParserOption {
	return func(cfg parserConfig) {
		if aud != "" {
			*cfg = append(*cfg, jwt.WithAudience(aud))
		}
	}
}

func WithIssuer(iss string) ParserOption {
	return func(cfg parserConfig) {
		if iss != "" {
			*cfg = append(*cfg, jwt.WithIssuer(iss))
		}
	}
}

func WithLeeway(d time.Duration) ParserOption {
	return func(o parserConfig) {
		if d > 0 {
			*o = append(*o, jwt.WithAcceptableSkew(d))
		}
	}
}

func WithHeaders(names ...string) ParserOption {
	return func(cfg parserConfig) {
		for _, n := range names {
			*cfg = append(*cfg, jwt.WithHeaderKey(n))
		}
	}
}

func WithKeySet(set jwk.Set) ParserOption {
	return func(cfg parserConfig) {
		if set != nil {
			*cfg = append(*cfg, jwt.WithKeySet(set))
		}
	}
}

func WithClock(clock util.Clock) ParserOption {
	return func(cfg parserConfig) {
		if clock != nil {
			*cfg = append(*cfg, jwt.WithClock(jwt.ClockFunc(clock)))
		}
	}
}

type parser struct {
	opts []jwt.ParseOption
}

func (p *parser) Parse(req *http.Request) (Claims, error) {
	opts := make([]jwt.ParseOption, len(p.opts)+1)
	copy(opts, p.opts)
	opts = append(opts, jwt.WithContext(req.Context()))
	tok, err := jwt.ParseRequest(req, opts...)
	if err != nil {
		return nil, err
	}
	return NewClaims(tok), nil
}
