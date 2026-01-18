package auth

import "github.com/deep-rent/nexus/jose/jwt"

type Claims struct {
	jwt.Reserved

	// TeamID holds the unique identifier of the team the user belongs to.
	TeamID string `json:"deep/team"`

	// Roles holds a list of CouchDB roles assigned to the user.
	Roles []string `json:"couch/roles"`
}
