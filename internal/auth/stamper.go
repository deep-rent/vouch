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

// headers contains the names of the HTTP headers used for proxy authentication.
type headers struct {
	// user is the header used to convey the authenticated user name.
	user string
	// roles is the header used to convey the authenticated user roles.
	roles string
	// token is the header used to convey the proxy token.
	token string
}

// unique reports whether all header names are distinct.
func (h headers) unique() bool {
	return h.user != h.roles && h.user != h.token && h.roles != h.token
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
//
// The function panics if the configured header names are not distinct, as
// this implies severe misconfiguration.
func NewStamper(opts ...StamperOption) Stamper {
	s := defaultStamper()
	for _, opt := range opts {
		opt(s)
	}
	if !s.headers.unique() {
		panic("duplicate header name")
	}
	return s
}

// defaultStamper initializes a Stamper with default settings.
func defaultStamper() *stamper {
	return &stamper{
		headers: headers{
			user:  DefaultUserHeader,
			roles: DefaultRolesHeader,
			token: DefaultTokenHeader,
		},
		signer: nil, // No signing by default; must be explicitly set
	}
}

// StamperOption defines a function for setting stamper options.
type StamperOption func(*stamper)

// WithUserHeader sets the name of the header used to convey the authenticated
// user name to CouchDB. If the provided name is empty or consists solely of
// whitespace, DefaultUserHeader remains in use. Otherwise the name will be
// canonicalized.
func WithUserHeader(name string) StamperOption {
	return func(s *stamper) {
		if name = strings.TrimSpace(name); name != "" {
			s.headers.user = http.CanonicalHeaderKey(name)
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
			s.headers.roles = http.CanonicalHeaderKey(name)
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
			s.headers.token = http.CanonicalHeaderKey(name)
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
	headers headers
	signer  signer.Signer
}

// Stamp implements the Stamper interface.
func (s *stamper) Stamp(req *http.Request, access Access) error {
	s.sanitize(req)
	user := access.User
	req.Header.Set(s.headers.user, user)
	if roles := access.Roles; len(roles) != 0 {
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
