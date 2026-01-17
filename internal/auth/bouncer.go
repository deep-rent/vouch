package auth

import (
	"errors"
	"net/http"
	"slices"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/vouch/internal/couch"
)

const RoleAdmin = "admin"

const userPrefix = "user_"
const teamPrefix = "team_"

var (
	ErrMissingToken            = errors.New("missing or invalid token")
	ErrInvalidToken            = errors.New("invalid token")
	ErrInsufficientPermissions = errors.New("insufficient permissions")
)

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
	// Check if it's the user's personal database:
	if u := claims.Subject(); u != "" && db == userPrefix+u {
		return true
	}
	// Check if the database belongs to the user's team:
	if t := claims.Team; t != "" && db == teamPrefix+t {
		return true
	}
	// The user has no access to this database.
	return false
}
