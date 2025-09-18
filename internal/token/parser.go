package token

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

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
	// errMissingHeader is returned when the token header is missing.
	errMissingHeader = errors.New("missing authentication header")
	// errInvalidScheme is returned when the token scheme is invalid.
	errInvalidScheme = errors.New("invalid authentication scheme")
)

// NewParser constructs a new Parser with the given options.
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

// defaultParserConfig initializes a configuration object with default settings.
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

// parserConfig holds all configurable parameters for a Parser.
type parserConfig struct {
	header string
	prefix string
	opts   []jwt.ParseOption
}

// ParserOption customizes the behavior of a Parser.
type ParserOption func(*parserConfig)

// WithAudience sets the expected audience claim ("aud") in the token. If the
// claim is absent or does not contain the given value, the token will be
// rejected.
//
// An empty value will be ignored. By default, no audience is required.
func WithAudience(aud string) ParserOption {
	return func(cfg *parserConfig) {
		if aud = strings.TrimSpace(aud); aud != "" {
			cfg.opts = append(cfg.opts, jwt.WithAudience(aud))
		}
	}
}

// WithIssuer sets the expected issuer claim ("iss") in the token. If the claim
// is absent or does not match, the token will be rejected.
//
// An empty value will be ignored. By default, no issuer is required.
func WithIssuer(iss string) ParserOption {
	return func(cfg *parserConfig) {
		if iss = strings.TrimSpace(iss); iss != "" {
			cfg.opts = append(cfg.opts, jwt.WithIssuer(iss))
		}
	}
}

// WithLeeway sets the acceptable clock skew for checking the token's
// temporal validity. This is useful to account for small differences
// between the issuer's and the verifier's clocks.
//
// A non-positive duration will be ignored. By default, no leeway is allowed.
func WithLeeway(d time.Duration) ParserOption {
	return func(cfg *parserConfig) {
		if d > 0 {
			cfg.opts = append(cfg.opts, jwt.WithAcceptableSkew(d))
		}
	}
}

// WithHeader sets the HTTP header from which to extract the token.
//
// An empty value will be ignored, and DefaultHeader will be used.
func WithHeader(k string) ParserOption {
	return func(cfg *parserConfig) {
		if k = strings.TrimSpace(k); k != "" {
			cfg.header = k
		}
	}
}

// WithScheme sets the expected authentication scheme in the token header.
//
// An empty value will be ignored, and DefaultScheme will be used. To omit the
// scheme entirely, pass OmitScheme. The scheme is case-sensitive and a single
// space is appended automatically to form the header prefix.
func WithScheme(s string) ParserOption {
	return func(cfg *parserConfig) {
		if s = strings.TrimSpace(s); s != "" {
			cfg.prefix = s + " "
		} else if s == OmitScheme {
			cfg.prefix = ""
		}
	}
}

// WithKeySet provides the JWK set to use for verifying signatures.
//
// If nil is given, this option is ignored. A valid key set must be specified
// for signature verification to work, or else all tokens will be rejected.
func WithKeySet(set KeySet) ParserOption {
	return func(cfg *parserConfig) {
		if set != nil {
			cfg.opts = append(cfg.opts, jwt.WithKeySet(set))
		}
	}
}

// WithClock sets the reference clock used for validating time-based claims.
//
// If nil is given, this option is ignored. By default, the system clock is
// used.
func WithClock(clock util.Clock) ParserOption {
	return func(cfg *parserConfig) {
		if clock != nil {
			cfg.opts = append(cfg.opts, jwt.WithClock(jwt.ClockFunc(clock)))
		}
	}
}

// parser is the default implementation of Parser.
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

	// Strip the access token from the outbound request
	req.Header.Del(p.header)

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
