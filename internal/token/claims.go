package token

import "github.com/lestrrat-go/jwx/v3/jwt"

// Claims holds the payload claims of a parsed JWT.
type Claims interface {
	// Get retrieves the claim value for the specified name.
	// If the claim is absent, nil will be returned.
	Get(name string) any
}

// NewClaims creates a new Claims instance from the given JWT token.
func NewClaims(token jwt.Token) Claims {
	return &claims{
		token: token,
	}
}

// Ensure claims satisfies the Claims interface.
var _ Claims = (*claims)(nil)

// claims is a concrete implementation of the Claims interface.
type claims struct {
	token jwt.Token
}

// Get implements the Claims interface.
func (c *claims) Get(name string) any {
	var v any
	if err := c.token.Get(name, &v); err != nil {
		return nil
	}
	return v
}
