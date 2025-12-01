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

const RoleAdmin = "admin"

const userPrefix = "user_"
const teamPrefix = "team_"

var (
  ErrMissingToken = errors.New("missing or invalid token")
  ErrInvalidToken = errors.New("invalid token")
  ErrInsufficientPermissions = errors.New("insufficient permissions")
)

type Claims struct {
	jwt.Reserved

	// Team holds the identifier for the team the user belongs to.
	Team string `json:"deep.rent/team"`

	// Roles is a list of roles assigned to the user.
	Roles []string `json:"deep.rent/roles"`
}

type Bouncer struct {
	verifier jwt.Verifier[*Claims]
}

func (b *Bouncer) Bounce(r *http.Request) (*Claims, error) {
	token := header.Credentials(r.Header, "Bearer")
	if token == "" {
		return nil, ErrMissingToken
	}
	claims, err := b.verifier.Verify([]byte(token))
	if err != nil {
		return nil, ErrInvalidToken
	}
	if !isAllowed(claims, r) {
		return nil, ErrInsufficientPermissions
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
  if u := claims.Sub; u != "" && db == userPrefix+u {
    return true
  }
  if t := claims.Team; t != "" && db == teamPrefix+t {
    return true
  }
  // The user has no access to this database.
	return false
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
