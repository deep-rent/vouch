package auth

import "net/http"

// Access defines the scope of access granted to an outgoing request.
type Access struct {
	// User is the name of the CouchDB user to authenticate as.
	// If empty, access should be denied.
	User string

	// Roles is the set of CouchDB roles to assign to the user.
	// It is nil or empty if User is empty, or if no roles are to be assigned.
	Roles []string
}

// Denied returns true if access is denied.
func (s Access) Denied() bool {
	return s.User == ""
}

type AccessError struct {
	// Cause is the wrapped error. It can be inspected using Unwrap.
	Cause error
	// StatusCode is the HTTP status code to respond with.
	StatusCode int
}

// Error implements the error interface.
func (e *AccessError) Error() string {
	return http.StatusText(e.StatusCode)
}

// Unwrap reveals the original error.
func (e *AccessError) Unwrap() error {
	return e.Cause
}

type Bouncer interface {
	Check(req *http.Request) (Access, *AccessError)
}
