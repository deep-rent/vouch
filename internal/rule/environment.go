package rule

import (
	"github.com/deep-rent/vouch/internal/token"
	"github.com/deep-rent/vouch/internal/util"
)

type Environment struct {
	claims token.Claims
	Method string
	Path   string
	DB     string
}

func NewEnvironment(claims token.Claims, method, path string) Environment {
	return Environment{
		claims: claims,
		Method: method,
		Path:   path,
		DB:     util.DB(path),
	}
}

func (e Environment) Claim(name string) any {
	return e.claims.Get(name)
}
