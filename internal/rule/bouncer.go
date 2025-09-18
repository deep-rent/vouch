package rule

import (
	"net/http"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/token"
)

// bouncer is the rule-based implementation of auth.Bouncer.
type bouncer struct {
	parser token.Parser
	engine Engine
}

// NewBouncer creates a new rule-based bouncer using the provided token parser
// and rule engine. The bouncer extracts a bearer token from incoming HTTP
// requests, parses it to obtain claims, and evaluates the authorization rules
// to determine access.
func NewBouncer(parser token.Parser, engine Engine) auth.Bouncer {
	return &bouncer{
		parser: parser,
		engine: engine,
	}
}

// Check implements the auth.Bouncer interface by parsing the token from the
// request and evaluating the rules to determine access.
func (b *bouncer) Check(req *http.Request) (auth.Access, *auth.AccessError) {
	claims, err := b.parser.Parse(req)
	if err != nil {
		// Missing or invalid token - 401 Unauthorized
		return auth.Access{}, &auth.AccessError{
			Cause:      err,
			StatusCode: http.StatusUnauthorized,
		}
	}
	env := NewEnvironment(claims, req.Method, req.URL.Path)
	access, err := b.engine.Eval(env)
	if err != nil {
		// Error during rule evaluation - 500 Internal Server Error
		return auth.Access{}, &auth.AccessError{
			Cause:      err,
			StatusCode: http.StatusInternalServerError,
		}
	}
	if access.Denied() {
		// Access denied by rules - 403 Forbidden
		return auth.Access{}, &auth.AccessError{
			Cause:      err,
			StatusCode: http.StatusForbidden,
		}
	}
	return access, nil
}
