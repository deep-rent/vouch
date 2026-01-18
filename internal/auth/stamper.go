package auth

import (
	"net/http"
	"strings"
)

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
