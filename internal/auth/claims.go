package auth

import "github.com/deep-rent/nexus/jose/jwt"

type Claims struct {
	jwt.Reserved

	// Tid holds the unique identifier of the team the user belongs to.
	Tid string `json:"tid"`

	// Scp holds a list of scopes assigned to the user.
	Scp []string `json:"scp"`
}
