package rules

import (
	"errors"

	"github.com/deep-rent/vouch/internal/config"
)

type Result struct {
	Pass bool
	User string
	Role string
}

// Engine evaluates authorization rules.
type Engine struct {
	rules []Rule
}

// NewEngine compiles the provided rules.
func NewEngine(rules []config.Rule) (*Engine, error) {
	if len(rules) == 0 {
		return nil, errors.New("at least one rule is required")
	}
	compiler := NewCompiler()
	compiled, err := compiler.Compile(rules)
	if err != nil {
		return nil, err
	}
	return &Engine{rules: compiled}, nil
}

// Eval evaluates rules in order and returns whether access is granted,
// and if so, the user and role(s) to forward to CouchDB. If no rule
// matches, access will be denied.
func (a *Engine) Eval(env Environment) (Result, error) {
	for _, r := range a.rules {
		skip, deny, user, role, err := r.Eval(env)
		if err != nil {
			return Result{}, err
		}
		if skip {
			continue
		}
		if deny {
			break
		}
		return Result{
			Pass: true,
			User: user,
			Role: role,
		}, nil
	}
	return Result{}, nil
}
