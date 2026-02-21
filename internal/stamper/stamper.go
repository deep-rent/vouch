package stamper

import (
	"net/http"
	"strings"

	"github.com/deep-rent/vouch/internal/bouncer"
)

type Config struct {
	UserNameHeader string
	RolesHeader    string
}

type Stamper struct {
	userNameHeader string
	rolesHeader    string
}

func New(cfg *Config) *Stamper {
	return &Stamper{
		userNameHeader: cfg.UserNameHeader,
		rolesHeader:    cfg.RolesHeader,
	}
}

func (s *Stamper) Stamp(req *http.Request, pass *bouncer.Pass) {
	req.Header.Set(s.userNameHeader, pass.UserName)

	if len(pass.Roles) != 0 {
		req.Header.Set(s.rolesHeader, strings.Join(pass.Roles, ","))
	}
}
