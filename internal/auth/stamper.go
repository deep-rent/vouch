package auth

import (
	"net/http"
	"strings"

	"github.com/deep-rent/vouch/internal/signer"
)

const (
	// DefaultUserHeader is the default header to convey the CouchDB user name.
	DefaultUserHeader = "X-Auth-CouchDB-User"
	// DefaultRolesHeader is the default header to convey the CouchDB user roles.
	DefaultRolesHeader = "X-Auth-CouchDB-Roles"
	// DefaultTokenHeader is the default header to convey the proxy token.
	DefaultTokenHeader = "X-Auth-CouchDB-Token"
)

// headers holds the names of the HTTP headers used for proxy authentication.
type headers struct {
	user  string
	roles string
	token string
}

// defaultHeaders returns a headers object initialized with default values.
func defaultHeaders() headers {
	return headers{
		user:  DefaultUserHeader,
		roles: DefaultRolesHeader,
		token: DefaultTokenHeader,
	}
}

// Stamper is responsible for attaching CouchDB-specific proxy authentication
// headers to outbound requests. It works in conjunction with a Bouncer.
type Stamper interface {
	// Stamp modifies the given HTTP request to include the appropriate
	// authentication headers based on the provided Access information.
	Stamp(req *http.Request, access Access) error
}

// NewStamper returns a Stamper configured with the given options.
// Be sure to align the header names if proxy headers are customized in the
// CouchDB configuration for proper operation. The configured names must be
// unique; ensuring this is the caller's responsibility.
func NewStamper(opts ...StamperOption) Stamper {
	cfg := defaultStamperConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &stamper{
		headers: cfg.headers,
		signer:  cfg.signer,
	}
}

// stamperConfig holds configuration settings for a Stamper.
type stamperConfig struct {
	headers headers
	signer  signer.Signer
}

// defaultStamperConfig initializes a stamperConfig with default settings.
func defaultStamperConfig() stamperConfig {
	return stamperConfig{
		headers: defaultHeaders(),
		signer:  nil, // No signing by default; must be explicitly set
	}
}

// StamperOption defines a function for setting stamper options.
type StamperOption func(*stamperConfig)

// WithUserHeader sets the name of the header used to convey the authenticated
// user name to CouchDB. If the provided name is empty or consists solely of
// whitespace, DefaultUserHeader remains in use. Otherwise the name will be
// canonicalized.
func WithUserHeader(k string) StamperOption {
	return func(cfg *stamperConfig) {
		if k = strings.TrimSpace(k); k != "" {
			cfg.headers.user = http.CanonicalHeaderKey(k)
		}
	}
}

// WithRolesHeader sets the name of the header used to convey the authenticated
// user roles to CouchDB. If the provided name is empty or consists solely of
// whitespace, DefaultRolesHeader remains in use. Otherwise the name will be
// canonicalized.
func WithRolesHeader(k string) StamperOption {
	return func(cfg *stamperConfig) {
		if k = strings.TrimSpace(k); k != "" {
			cfg.headers.roles = http.CanonicalHeaderKey(k)
		}
	}
}

// WithTokenHeader sets the name of the header used to convey the authentication
// token to CouchDB. If the provided name is empty or consists solely of
// whitespace, DefaultTokenHeader remains in use. Otherwise the name will be
// canonicalized.
func WithTokenHeader(k string) StamperOption {
	return func(cfg *stamperConfig) {
		if k = strings.TrimSpace(k); k != "" {
			cfg.headers.token = http.CanonicalHeaderKey(k)
		}
	}
}

// WithSigner sets the Signer used to generate proxy authentication tokens.
// This is crucial for establishing trust between the proxy service and CouchDB.
//
// If nil is given, no tokens will be included in requests (default). For
// production use, users are strongly advised to provide a secure Signer.
func WithSigner(s signer.Signer) StamperOption {
	return func(cfg *stamperConfig) {
		cfg.signer = s // nilable
	}
}

// stamper is the default implementation of Stamper.
type stamper struct {
	headers headers
	signer  signer.Signer
}

// Stamp implements the Stamper interface.
func (s *stamper) Stamp(req *http.Request, access Access) error {
	s.sanitize(req)
	user := access.User
	req.Header.Set(s.headers.user, user)
	if roles := access.Roles; len(roles) != 0 {
		// Roles are joined with commas, as CouchDB expects
		req.Header.Set(s.headers.roles, strings.Join(roles, ","))
	}
	if s.signer != nil {
		req.Header.Set(s.headers.token, s.signer.Sign(user))
	}
	return nil
}

// sanitize clears any existing headers to prevent malicious forgery.
func (s *stamper) sanitize(req *http.Request) {
	req.Header.Del(s.headers.user)
	req.Header.Del(s.headers.roles)
	req.Header.Del(s.headers.token)
}
