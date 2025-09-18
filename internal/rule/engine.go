package rule

import (
	"fmt"

	"github.com/deep-rent/vouch/internal/auth"
)

// Engine evaluates a list of rules in order to make an access decision.
type Engine []Rule

// Eval evaluates the rules in order and stops at the first
// definitive decision.
func (s Engine) Eval(env Environment) (auth.Access, error) {
	for i, r := range s {
		d, err := r.Decide(env)
		if err != nil {
			return auth.Access{}, fmt.Errorf("rule[%d].%w", i, err)
		}
		// The rule decided to skip; try the next one.
		if d.Skip {
			continue
		}
		// The rule allowed or denied access.
		return d.Access, nil
	}
	// If no rule decided, deny by default.
	return auth.Access{}, nil
}
