package auth

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/vouch/internal/couch"
)

const RoleAdmin = "couch_admin"

type Claims struct {
	jwt.Reserved

	// Tenant holds the identifier for the tenant the user belongs to.
	Tenant string `json:"deep.rent/tenant"`

	// Roles is a list of roles assigned to the user.
	Roles []string `json:"deep.rent/roles"`
}

type Bouncer struct {
	verifier jwt.Verifier[*Claims]
}

func (b *Bouncer) Bounce(r *http.Request) (*Claims, error) {
	token := header.Credentials(r.Header, "Bearer")
	if token == "" {
		return nil, errors.New("")
	}
	claims, err := b.verifier.Verify([]byte(token))
	if err != nil {
		return nil, errors.New("")
	}
	if !isAllowed(claims, r) {
		return nil, errors.New("")
	}
	return claims, nil
}

func isAllowed(claims *Claims, r *http.Request) bool {
	if slices.Contains(claims.Roles, RoleAdmin) {
		return true
	}
	db := couch.Database(r.URL.Path)
	if db == "" {
		return false
	}
	return db == "user_"+claims.Sub || db == "tenant_"+claims.Tenant
}

type Stamper struct {
	userHeader string
	roleHeader string
}

func (s *Stamper) Stamp(claims *Claims, r *http.Request) {
	r.Header.Set(s.userHeader, claims.Sub)

	if len(claims.Roles) != 0 {
		r.Header.Set(s.roleHeader, strings.Join(claims.Roles, ","))
	}
}
