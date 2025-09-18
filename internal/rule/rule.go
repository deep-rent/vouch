package rule

import (
	"fmt"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/util"
)

// Decision holds the verdict rendered after evaluating a single Rule.
// It indicates what to do next in the evaluation process of multiple rules.
type Decision struct {
	// Access is the access granted by the rule if it wasn't skipped.
	auth.Access

	// Skip is true if the rule's condition did not match.
	// It tells the caller to ignore this rule and continue evaluating the next.
	Skip bool
}

// Rule represents a compiled authorization rule.
type Rule interface {
	// Decide evaluates the rule against the specified environment.
	Decide(env Environment) (Decision, error)
}

// rule is the concrete implementation of Rule.
type rule struct {
	deny  bool        // whether this rule denies or grants access
	when  *vm.Program // required; evaluates to bool
	user  *vm.Program // required if deny is false; evaluates to string
	roles *vm.Program // optional; evaluates to []any
}

// matches checks if the rule's condition is satisfied.
func (r *rule) matches(env Environment) (bool, error) {
	w, err := exec[bool](r.when, env)
	if err != nil {
		return false, fmt.Errorf("when: %w", err)
	}
	return w, nil
}

// access determines the Access defined by the rule.
func (r *rule) access(env Environment) (auth.Access, error) {
	user, err := exec[string](r.user, env)
	if err != nil {
		return auth.Access{}, fmt.Errorf("user: %w", err)
	}
	if user == "" {
		return auth.Access{}, fmt.Errorf("user: must not be empty")
	}
	var roles []string = nil
	if r.roles != nil {
		a, err := exec[[]any](r.roles, env)
		if err != nil {
			return auth.Access{}, fmt.Errorf("roles: %w", err)
		}
		roles = make([]string, len(a))
		for i, v := range a {
			s, err := util.Conv[string](v)
			if err != nil {
				return auth.Access{}, fmt.Errorf("roles[%d]: %w", i, err)
			}
			roles[i] = s
		}
	}
	return auth.Access{User: user, Roles: roles}, nil
}

// Decide implements the Rule interface.
func (r *rule) Decide(env Environment) (Decision, error) {
	match, err := r.matches(env)
	if err != nil {
		return Decision{}, err
	}
	if !match {
		return Decision{Skip: true}, nil
	}
	if r.deny {
		return Decision{}, nil
	}
	access, err := r.access(env)
	if err != nil {
		return Decision{}, err
	}
	return Decision{Access: access}, nil
}

// exec executes a compiled expression and converts the result
// to the desired type T.
func exec[T any](p *vm.Program, env Environment) (T, error) {
	v, err := expr.Run(p, env)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("execute expr: %w", err)
	}
	return util.Conv[T](v)
}
