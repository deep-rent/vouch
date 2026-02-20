package stamper

import (
	"net/http"
	"strings"

	"github.com/deep-rent/vouch/internal/bouncer"
	"github.com/deep-rent/vouch/internal/config"
)

type Stamper struct {
	userHeader  string
	rolesHeader string
}

func New(cfg *config.Config) *Stamper {
	return &Stamper{
		userHeader:  cfg.UserHeader,
		rolesHeader: cfg.RolesHeader,
	}
}

func (s *Stamper) Stamp(req *http.Request, pass *bouncer.Pass) {
	req.Header.Set(s.userHeader, pass.User)
	if len(pass.Roles) > 0 {
		req.Header.Set(s.rolesHeader, strings.Join(pass.Roles, ","))
	}
	req.Header.Del("Authorization")
}
