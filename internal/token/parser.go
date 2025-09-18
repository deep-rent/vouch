package token

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/deep-rent/vouch/internal/util"
)

// Parser parses JWTs from HTTP requests.
type Parser interface {
	// Parse extracts and parses the access token from the request headers.
	Parse(req *http.Request) (Claims, error)
}

const (
	// DefaultHeader is the default HTTP header used to transmit the token.
	DefaultHeader = "Authorization"
	// DefaultScheme is the default authentication scheme in the token header.
	DefaultScheme = "Bearer"
)

// OmitScheme indicates that no scheme is used in the token header.
const OmitScheme = "none"

var (
	errMissingHeader = errors.New("missing authentication header")
	errInvalidScheme = errors.New("invalid authentication scheme")
)

func NewParser(opts ...ParserOption) Parser {
	cfg := defaultParserConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &parser{
		header: cfg.header,
		prefix: cfg.prefix,
		opts:   cfg.opts,
	}
}

func defaultParserConfig() parserConfig {
	return parserConfig{
		header: DefaultHeader,
		prefix: DefaultScheme + " ",
		opts: []jwt.ParseOption{
			jwt.WithValidate(true),
			jwt.WithPedantic(true),
		},
	}
}

type parserConfig struct {
	header string
	prefix string
	opts   []jwt.ParseOption
}

type ParserOption func(*parserConfig)

func WithAudience(aud string) ParserOption {
	return func(cfg *parserConfig) {
		if aud != "" {
			cfg.opts = append(cfg.opts, jwt.WithAudience(aud))
		}
	}
}

func WithIssuer(iss string) ParserOption {
	return func(cfg *parserConfig) {
		if iss != "" {
			cfg.opts = append(cfg.opts, jwt.WithIssuer(iss))
		}
	}
}

func WithLeeway(d time.Duration) ParserOption {
	return func(cfg *parserConfig) {
		if d > 0 {
			cfg.opts = append(cfg.opts, jwt.WithAcceptableSkew(d))
		}
	}
}

func WithHeader(name string) ParserOption {
	return func(cfg *parserConfig) {
		if name != "" {
			cfg.header = name
		}
	}
}

func WithScheme(name string) ParserOption {
	return func(cfg *parserConfig) {
		if name != "" {
			cfg.prefix = name + " "
		} else if name == OmitScheme {
			cfg.prefix = ""
		}
	}
}

func WithKeySet(set jwk.Set) ParserOption {
	return func(cfg *parserConfig) {
		if set != nil {
			cfg.opts = append(cfg.opts, jwt.WithKeySet(set))
		}
	}
}

func WithClock(clock util.Clock) ParserOption {
	return func(cfg *parserConfig) {
		if clock != nil {
			cfg.opts = append(cfg.opts, jwt.WithClock(jwt.ClockFunc(clock)))
		}
	}
}

type parser struct {
	header string
	prefix string
	opts   []jwt.ParseOption
}

// Parse implements the Parser interface.
func (p *parser) Parse(req *http.Request) (Claims, error) {
	opts := make([]jwt.ParseOption, len(p.opts)+1)
	copy(opts, p.opts)
	opts = append(opts, jwt.WithContext(req.Context()))

	raw, err := p.extract(req)
	if err != nil {
		return nil, err
	}
	tok, err := jwt.ParseString(raw, opts...)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}
	return NewClaims(tok), nil
}

// extract reads out the token from the request header.
func (p *parser) extract(req *http.Request) (string, error) {
	auth := req.Header.Get(p.header)
	if auth == "" {
		return "", errMissingHeader
	}
	if p.prefix != "" && !strings.HasPrefix(auth, p.prefix) {
		return "", errInvalidScheme
	}
	return auth[len(p.prefix):], nil
}
