package guard

import (
	"errors"

	"github.com/deep-rent/vouch/internal/rule"
)

// Guard evaluates authorization rules.
type Guard struct {
	rules []rule.Rule
}

// NewGuard compiles the provided rules.
func New(rules []rule.Config) (*Guard, error) {
	if len(rules) == 0 {
		return nil, errors.New("at least one rule is required")
	}
	compiler := rule.NewCompiler()
	compiled, err := compiler.Compile(rules)
	if err != nil {
		return nil, err
	}
	return &Guard{rules: compiled}, nil
}

// Authorize evaluates rules in order and returns whether access is granted,
// and if so, the user and role(s) to forward to CouchDB. If no rule
// matches, access is denied.
func (g *Guard) Authorize(env rule.Environment) (
	pass bool,
	user string,
	role string,
	err error,
) {
	for _, rule := range g.rules {
		skip, deny, u, r, e := rule.Eval(env)
		if e != nil {
			err = e
			return
		}
		if skip {
			continue
		}
		if deny {
			return
		}
		pass = true
		user = u
		role = r
		return
	}
	return
}
