package rule

import (
	"errors"
	"fmt"

	"github.com/deep-rent/vouch/internal/auth"
)

// Engine evaluates a list of rules in order to make an access decision.
type Engine []Rule

// ErrNoMatch indicates that access has been denied because no rule matched.
var ErrNoMatch = errors.New("no rule matched")

// Eval evaluates the rules in order and stops at the first
// definitive decision. It returns an auth.AccessError if either no rule
// matched or if a rule denied access. Other errors signal unexpected
// circumstances and should be treated as internal errors.
func (s Engine) Eval(env Environment) (auth.Access, error) {
	cause := ErrNoMatch
	for i, r := range s {
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
