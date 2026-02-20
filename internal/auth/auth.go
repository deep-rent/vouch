package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/deep-rent/nexus/header"
	"github.com/deep-rent/nexus/jose/jwt"
)

var (
	ErrMissingToken = errors.New("missing or invalid token")
	ErrInvalidToken = errors.New("invalid token")
)

type Bouncer struct {
	verifier jwt.Verifier[*jwt.DynamicClaims]
}

func (b *Bouncer) Bounce(r *http.Request) (*jwt.DynamicClaims, error) {
	token := header.Credentials(r.Header, "Bearer")
	if token == "" {
		return nil, ErrMissingToken
	}
	claims, err := b.verifier.Verify([]byte(token))
	if err != nil || claims.Sub == "" {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

type Stamper struct {
	roleClaim  string
	userHeader string
	roleHeader string
}

func (s *Stamper) Stamp(claims *jwt.DynamicClaims, r *http.Request) {
	r.Header.Set(s.userHeader, claims.Sub)

	roles, ok := jwt.Get[[]string](claims, s.roleClaim)

	if ok && len(roles) != 0 {
		r.Header.Set(s.roleHeader, strings.Join(roles, ","))
	}
}

type Guard struct {
	bouncer *Bouncer
	stamper *Stamper
}
