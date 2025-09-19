package rule

import (
	"errors"
	"fmt"

	"github.com/deep-rent/vouch/internal/auth"
)

// errNoMatch indicates that access has been denied because no rule matched.
var errNoMatch = errors.New("no rule matched")

// Engine evaluates a list of rules in order to make an access decision.
type Engine []Rule

// Eval evaluates the rules in order and stops at the first
// definitive decision. It returns an auth.AccessError if either no rule
// matched or if a rule denied access. Other errors signal unexpected
// circumstances and should be treated as internal errors.
func (e Engine) Eval(env Environment) (auth.Access, error) {
	cause := errNoMatch
	for i, r := range e {
		d, err := r.Decide(env)
		if err != nil {
			return auth.Access{}, fmt.Errorf("rule %d: %w", i, err)
		}
		// The rule decided to skip; try the next one.
		if d.Skip {
			continue
		}
		if d.Deny {
			cause = fmt.Errorf("rule %d matched", i)
			break
		}
		// The rule allowed or denied access.
		return d.Access, nil
	}
	return auth.Access{}, auth.NewAccessError(
		auth.ReasonInsufficientPrivilege, cause,
	)
}

// Empty checks whether the engine has no rules. An empty engine
// always denies access.
func (e Engine) Empty() bool {
	return len(e) == 0
}
