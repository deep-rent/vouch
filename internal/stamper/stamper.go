package stamper

import (
	"net/http"
	"strings"

	"github.com/deep-rent/vouch/internal/bouncer"
)

type Config struct {
	NameHeader string
	RoleHeader string
}

type Stamper struct {
	nameHeader string
	roleHeader string
}

func New(cfg *Config) *Stamper {
	return &Stamper{
		nameHeader: cfg.NameHeader,
		roleHeader: cfg.RoleHeader,
	}
}

func (s *Stamper) Stamp(req *http.Request, u *bouncer.User) {
	req.Header.Set(s.nameHeader, u.Name)

	if len(u.Roles) != 0 {
		roles := strings.Join(u.Roles, ",")
		req.Header.Set(s.roleHeader, roles)
	}
}
