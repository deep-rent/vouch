package rule

import (
	"github.com/deep-rent/vouch/internal/token"
	"github.com/deep-rent/vouch/internal/util"
)

// Environment provides contextual information for rule evaluation.
// The public fields and methods are directly accessible in rule expressions.
type Environment struct {
	claims token.Claims
	Method string
	Path   string
	DB     string
}

// NewEnvironment creates a new Environment with the given parameters.
func NewEnvironment(claims token.Claims, method, path string) Environment {
	return Environment{
		claims: claims,
		Method: method,
		Path:   path,
		DB:     util.DB(path),
	}
}

// Claim retrieves a claim value by name from the token claims. If the claim
// does not exist, it returns nil.
func (e Environment) Claim(name string) any {
	return e.claims.Get(name)
}
