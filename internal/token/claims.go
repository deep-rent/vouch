package token

import "github.com/lestrrat-go/jwx/v3/jwt"

// Claims holds the payload claims of a parsed JWT.
type Claims interface {
	Get(name string) any
}

func NewClaims(token jwt.Token) Claims {
	return &claims{
		token: token,
	}
}

var _ Claims = (*claims)(nil)

type claims struct {
	token jwt.Token
}

// Get retrieves the claim value for the specified name.
// If the claim is absent, nil will be returned.
func (c *claims) Get(name string) any {
	var v any
	if err := c.token.Get(name, &v); err != nil {
		return nil
	}
	return v
}
