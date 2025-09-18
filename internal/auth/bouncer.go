package auth

import (
	"net/http"
)

// Access defines the scope of access granted to an outgoing request.
type Access struct {
	// User is the name of the CouchDB user to authenticate as.
	User string
	// Roles is the set of CouchDB roles to assign to the user.
	// It is nil or empty if no roles are to be assigned.
	Roles []string
}

// Reason distinguishes the specific causes of access denial.
type Reason int

const (
	// ReasonAuthenticationFailure implies that authentication was unsuccessful,
	// e.g., due to a missing or invalid token.
	ReasonAuthenticationFailure Reason = iota

	// ReasonInsufficientPrivilege implies that authentication succeeded but
	// the authenticated entity does not have sufficient permissions to access
	// the requested resource.
	ReasonInsufficientPrivilege
)

// reasonText maps a Reason to a human-readable string for use in error
// messages.
func reasonText(r Reason) string {
	switch r {
	case ReasonInsufficientPrivilege:
		return "insufficient privilege"
	default:
		return "authentication failure"
	}
}

// statusCode maps a Reason to a corresponding HTTP status code for use in
// client-facing responses.
func statusCode(r Reason) int {
	switch r {
	case ReasonInsufficientPrivilege:
		return http.StatusForbidden
	default:
		return http.StatusUnauthorized
	}
}

// AccessError represents a deliberate denial of access.
//
// Unlike unexpected errors, AccessError is an intentional signal that an
// HTTP handler (like a Guard) should inspect.
type AccessError struct {
	// Err is the wrapped error. It can be inspected using Unwrap.
	Err error
	// Reason indicates why access was denied.
	Reason Reason
}

// NewAccessError creates a new AccessError with the given reason and cause.
func NewAccessError(reason Reason, err error) *AccessError {
	return &AccessError{
		Err:    err,
		Reason: reason,
	}
}

// Error returns the reason text followed by the wrapped error message.
func (e *AccessError) Error() string {
	if e.Err == nil {
		// There should always be a cause, but just in case...
		return reasonText(e.Reason)
	}
	// The slog.Logger does not handle nested errors well, so we take care of
	// formatting the message ourselves.
	return reasonText(e.Reason) + ": " + e.Err.Error()
}

// StatusCode returns the appropriate HTTP status code to respond with.
func (e *AccessError) StatusCode() int {
	return statusCode(e.Reason)
}

// Unwrap reveals the original error.
func (e *AccessError) Unwrap() error {
	return e.Err
}

// Bouncer is responsible for authorizing inbound HTTP requests before they
// reach CouchDB.
type Bouncer interface {
	// Check inspects the incoming HTTP request and decides whether to allow or
	// deny access.
	//
	// If successful, an Access value is returned that describes the permissions
	// granted to the request. This value should be passed to a Stamper in order
	// to authenticate the outbound request against CouchDB.
	//
	// If the request is to be denied, an *AccessError will be returned. Other
	// errors should be treated as internal.
	Check(req *http.Request) (Access, error)
}
