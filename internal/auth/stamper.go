package auth

import (
	"net/http"
	"strings"

	"github.com/deep-rent/vouch/internal/signer"
)

const (
	DefaultUserHeader  = "X-Auth-CouchDB-User"
	DefaultRolesHeader = "X-Auth-CouchDB-Roles"
	DefaultTokenHeader = "X-Auth-CouchDB-Token"
)

type Stamper interface {
	Stamp(req *http.Request, access Access)
}

func NewStamper(opts ...StamperOption) Stamper {
	s := &stamper{
		userHeader:  DefaultUserHeader,
		rolesHeader: DefaultRolesHeader,
		tokenHeader: DefaultTokenHeader,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type StamperOption func(*stamper)

func WithUserHeader(name string) StamperOption {
	return func(s *stamper) {
		if name = strings.TrimSpace(name); name != "" {
			s.userHeader = http.CanonicalHeaderKey(name)
		}
	}
}

func WithRolesHeader(name string) StamperOption {
	return func(s *stamper) {
		if name = strings.TrimSpace(name); name != "" {
			s.rolesHeader = http.CanonicalHeaderKey(name)
		}
	}
}

func WithTokenHeader(name string) StamperOption {
	return func(s *stamper) {
		if name = strings.TrimSpace(name); name != "" {
			s.tokenHeader = http.CanonicalHeaderKey(name)
		}
	}
}

func WithSigner(signer signer.Signer) StamperOption {
	return func(s *stamper) {
		s.signer = signer
	}
}

type stamper struct {
	userHeader  string
	rolesHeader string
	tokenHeader string
	signer      signer.Signer
}

func (s *stamper) Stamp(req *http.Request, access Access) {
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
}
