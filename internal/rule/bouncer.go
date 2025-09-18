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
func (b *bouncer) Check(req *http.Request) (auth.Access, error) {
	claims, err := b.parser.Parse(req)
	if err != nil {
		// Missing or invalid token
		return auth.Access{}, auth.NewAccessError(
			auth.ReasonAuthenticationFailure, err,
		)
	}
	method, path := req.Method, req.URL.Path
	// The engine returns an auth.AccessError if access is denied; no further
	// wrapping is needed.
	return b.engine.Eval(NewEnvironment(claims, method, path))
}
