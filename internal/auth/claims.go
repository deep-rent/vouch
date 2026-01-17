package auth

import "github.com/deep-rent/nexus/jose/jwt"

type Claims struct {
	jwt.Reserved

	// Team holds the identifier for the team the user belongs to.
	Team string `json:"deep.rent/team"`

	// Roles is a list of roles assigned to the user.
	Roles []string `json:"deep.rent/roles"`
}
