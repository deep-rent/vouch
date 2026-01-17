package auth

import (
	"errors"
	"net/http"
	"slices"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/vouch/internal/couch"
)

const scopeAdmin = "couch:admin"

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
	// Admins have access to everything:
	if slices.Contains(claims.Scp, scopeAdmin) {
		return true
	}
	db := couch.Database(r.URL.Path)
	if db == "" {
		return false
	}
	// Check if it's the user's database:
	if u := claims.Sub; u != "" && db == userPrefix+u {
		return true
	}
	// Check if it's the team's database:
	if t := claims.Tid; t != "" && db == teamPrefix+t {
		return true
	}
	// Else, the user has no access to this database.
	return false
}
