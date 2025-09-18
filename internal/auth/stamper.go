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
		userHeader:  DefaultUserHeader,
		rolesHeader: DefaultRolesHeader,
		tokenHeader: DefaultTokenHeader,
	}
}

// StamperOption defines a function for setting stamper options.
type StamperOption func(*stamper)

// WithUserHeader sets the name of the header used to convey the authenticated
// user name to CouchDB. If the provided name is empty or consists solely of
// whitespace, DefaultUserHeader remains in use.
func WithUserHeader(name string) StamperOption {
	return func(s *stamper) {
		if name = strings.TrimSpace(name); name != "" {
			s.userHeader = http.CanonicalHeaderKey(name)
		}
	}
}

// WithRolesHeader sets the name of the header used to convey the authenticated
// user roles to CouchDB. If the provided name is empty or consists solely of
// whitespace, DefaultRolesHeader remains in use.
func WithRolesHeader(name string) StamperOption {
	return func(s *stamper) {
		if name = strings.TrimSpace(name); name != "" {
			s.rolesHeader = http.CanonicalHeaderKey(name)
		}
	}
}

// WithTokenHeader sets the name of the header used to convey the authentication
// token to CouchDB. If the provided name is empty or consists solely of
// whitespace, DefaultTokenHeader remains in use.
func WithTokenHeader(name string) StamperOption {
	return func(s *stamper) {
		if name = strings.TrimSpace(name); name != "" {
			s.tokenHeader = http.CanonicalHeaderKey(name)
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
	userHeader  string
	rolesHeader string
	tokenHeader string
	signer      signer.Signer
}

// Stamp implements the Stamper interface.
func (s *stamper) Stamp(req *http.Request, access Access) error {
	// Clear any existing headers to prevent malicious forgery.
	req.Header.Del(s.userHeader)
	req.Header.Del(s.rolesHeader)
	req.Header.Del(s.tokenHeader)

	req.Header.Set(s.userHeader, access.User)

	if roles := access.Roles; len(roles) != 0 {
		req.Header.Set(s.rolesHeader, strings.Join(roles, ","))
	}

	if s.signer != nil {
		req.Header.Set(s.tokenHeader, s.signer.Sign(access.User))
	}

	return nil
}
