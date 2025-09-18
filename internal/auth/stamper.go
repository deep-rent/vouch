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

// Headers contains the names of the HTTP headers used for proxy authentication.
type Headers struct {
	// User is the header used to convey the authenticated user name.
	User string
	// Roles is the header used to convey the authenticated user roles.
	Roles string
	// Token is the header used to convey the proxy token.
	Token string
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
// CouchDB configuration for proper operation.
func NewStamper(opts ...StamperOption) Stamper {
	s := defaultStamper()
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// defaultStamper initializes a Stamper with default settings.
func defaultStamper() *stamper {
	return &stamper{
		headers: Headers{
			User:  DefaultUserHeader,
			Roles: DefaultRolesHeader,
			Token: DefaultTokenHeader,
		},
		signer: nil, // No signing by default; must be explicitly set
	}
}

// StamperOption defines a function for setting stamper options.
type StamperOption func(*stamper)

// WithHeaders sets all header names at once. Individual names will be
// trimmed and canonicalized. Empty or whitespace-only names will be ignored
// and the corresponding defaults remain in use.
func WithHeaders(h Headers) StamperOption {
	return func(s *stamper) {
		WithUserHeader(h.User)(s)
		WithRolesHeader(h.Roles)(s)
		WithTokenHeader(h.Token)(s)
	}
}

// WithUserHeader sets the name of the header used to convey the authenticated
// user name to CouchDB. If the provided name is empty or consists solely of
// whitespace, DefaultUserHeader remains in use. Otherwise the name will be
// canonicalized.
func WithUserHeader(name string) StamperOption {
	return func(s *stamper) {
		if name = strings.TrimSpace(name); name != "" {
			s.headers.User = http.CanonicalHeaderKey(name)
		}
	}
}

// WithRolesHeader sets the name of the header used to convey the authenticated
// user roles to CouchDB. If the provided name is empty or consists solely of
// whitespace, DefaultRolesHeader remains in use. Otherwise the name will be
// canonicalized.
func WithRolesHeader(name string) StamperOption {
	return func(s *stamper) {
		if name = strings.TrimSpace(name); name != "" {
			s.headers.Roles = http.CanonicalHeaderKey(name)
		}
	}
}

// WithTokenHeader sets the name of the header used to convey the authentication
// token to CouchDB. If the provided name is empty or consists solely of
// whitespace, DefaultTokenHeader remains in use. Otherwise the name will be
// canonicalized.
func WithTokenHeader(name string) StamperOption {
	return func(s *stamper) {
		if name = strings.TrimSpace(name); name != "" {
			s.headers.Token = http.CanonicalHeaderKey(name)
		}
	}
}

// WithSigner sets the Signer used to generate proxy authentication tokens.
// If nil is given, no tokens will be included in requests (default). For
// production use, a secure Signer is strongly recommended.
func WithSigner(signer signer.Signer) StamperOption {
	return func(s *stamper) {
		s.signer = signer
	}
}

// stamper is the default implementation of Stamper.
type stamper struct {
	headers Headers
	signer  signer.Signer
}

// Stamp implements the Stamper interface.
func (s *stamper) Stamp(req *http.Request, access Access) error {
	s.sanitize(req)
	user := access.User
	req.Header.Set(s.headers.User, user)
	if roles := access.Roles; len(roles) != 0 {
		req.Header.Set(s.headers.Roles, strings.Join(roles, ","))
	}
	if s.signer != nil {
		req.Header.Set(s.headers.Token, s.signer.Sign(user))
	}
	return nil
}

// sanitize clears any existing headers to prevent malicious forgery.
func (s *stamper) sanitize(req *http.Request) {
	req.Header.Del(s.headers.User)
	req.Header.Del(s.headers.Roles)
	req.Header.Del(s.headers.Token)
}
