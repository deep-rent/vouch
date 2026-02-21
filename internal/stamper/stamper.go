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

func (s *Stamper) Stamp(req *http.Request, user *bouncer.User) {
	req.Header.Set(s.userNameHeader, user.Name)

	if len(user.Roles) != 0 {
		roles := strings.Join(user.Roles, ",")
		req.Header.Set(s.rolesHeader, roles)
	}
}
