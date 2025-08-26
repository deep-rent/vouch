// Copyright (c) 2025-present deep.rent GmbH (https://www.deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package traefikplugincouchdb

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// Rule defines one authorization rule.
// Rules are evaluated in order; the first matching rule decides.
type Rule struct {
	// Mode is "allow" or "deny".
	Mode string `json:"mode"`

	// When is a boolean expression that decides if the rule matches.
	// Environment exposes: claims (alias c), method, path, db.
	When string `json:"when"`

	// User is a string expression for CouchDB username (required for allow).
	User string `json:"user,omitempty"`

	// Role is an expression producing a single string (optional).
	// You can return either a single role or a comma-separated list.
	Role string `json:"role,omitempty"`
}

// Environment is the evaluation environment.
type Environment struct {
	Claims map[string]any
	C      map[string]any // alias

	// HTTP exchange context
	Method string
	Path   string
	DB     string
}

// Authorizer compiles and evaluates rules.
type Authorizer struct {
	rules []compiledRule
}

type compiledRule struct {
	mode string
	when *vm.Program
	user *vm.Program // only for "allow"
	role *vm.Program // optional
}

const (
	modeAllow = "allow"
	modeDeny  = "deny"
)

// ruleCompiler encapsulates compilation details.
type ruleCompiler struct {
	opts []expr.Option
}

func newRuleCompiler() *ruleCompiler {
	return &ruleCompiler{opts: []expr.Option{expr.Env(Environment{})}}
}

func (c *ruleCompiler) compileAll(rules []Rule) ([]compiledRule, error) {
	out := make([]compiledRule, 0, len(rules))
	for i, rr := range rules {
		cr, err := c.compileOne(i, rr)
		if err != nil {
			return nil, err
		}
		out = append(out, cr)
	}
	return out, nil
}

func (c *ruleCompiler) compileOne(i int, r Rule) (compiledRule, error) {
	mode := strings.ToLower(strings.TrimSpace(r.Mode))
	if mode != modeAllow && mode != modeDeny {
		return compiledRule{}, fmt.Errorf(
			"rules[%d].mode must be '%s' or '%s'",
			i, modeAllow, modeDeny,
		)
	}

	when := strings.TrimSpace(r.When)
	if when == "" {
		return compiledRule{}, fmt.Errorf(
			"rules[%d].when is required", i,
		)
	}
	whenProg, err := expr.Compile(when, c.opts...)
	if err != nil {
		return compiledRule{}, fmt.Errorf(
			"compile rules[%d].when: %w", i, err,
		)
	}

	var userProg, roleProg *vm.Program
	if mode == modeDeny {
		if strings.TrimSpace(r.User) != "" {
			return compiledRule{}, fmt.Errorf(
				"rules[%d]: user must not be set for %s mode",
				i, modeDeny,
			)
		}
		if strings.TrimSpace(r.Role) != "" {
			return compiledRule{}, fmt.Errorf(
				"rules[%d]: role must not be set for %s mode",
				i, modeDeny,
			)
		}
	} else {
		u := strings.TrimSpace(r.User)
		if u == "" {
			return compiledRule{}, fmt.Errorf(
				"rules[%d].user is required in %s mode",
				i, modeAllow,
			)
		}
		userProg, err = expr.Compile(u, c.opts...)
		if err != nil {
			return compiledRule{}, fmt.Errorf(
				"compile rules[%d].user: %w", i, err,
			)
		}
		if s := strings.TrimSpace(r.Role); s != "" {
			roleProg, err = expr.Compile(s, c.opts...)
			if err != nil {
				return compiledRule{}, fmt.Errorf(
					"compile rules[%d].role: %w", i, err,
				)
			}
		}
	}

	return compiledRule{
		mode: mode,
		when: whenProg,
		user: userProg,
		role: roleProg,
	}, nil
}

// NewAuthorizer compiles the provided rules.
func NewAuthorizer(rules []Rule) (*Authorizer, error) {
	if len(rules) == 0 {
		return nil, errors.New("at least one rule is required")
	}
	compiled, err := newRuleCompiler().compileAll(rules)
	if err != nil {
		return nil, err
	}
	return &Authorizer{rules: compiled}, nil
}

// Authorize evaluates rules in order and returns:
// allowed, username, role, error. If no rule matches, it's denied.
func (a *Authorizer) Authorize(
	ctx context.Context,
	env Environment,
) (bool, string, string, error) {
	for _, r := range a.rules {
		whenRes, err := expr.Run(r.when, env)
		if err != nil {
			return false, "", "", fmt.Errorf("eval when: %w", err)
		}
		ok, isBool := whenRes.(bool)
		if !isBool {
			return false, "", "", fmt.Errorf("when must evaluate to bool, got %T", whenRes)
		}
		if !ok {
			continue
		}

		if r.mode == modeDeny {
			return false, "", "", nil
		}

		userRes, err := expr.Run(r.user, env)
		if err != nil {
			return false, "", "", fmt.Errorf("eval user: %w", err)
		}
		user, isStr := userRes.(string)
		if !isStr || strings.TrimSpace(user) == "" {
			return false, "", "", fmt.Errorf("user must evaluate to non-empty string")
		}

		var role string
		if r.role != nil {
			val, err := expr.Run(r.role, env)
			if err != nil {
				return false, "", "", fmt.Errorf("eval role: %w", err)
			}
			switch v := val.(type) {
			case string:
				role = v
			case nil:
				role = ""
			default:
				return false, "", "", fmt.Errorf("role must evaluate to string, got %T", val)
			}
		}

		return true, user, role, nil
	}
	return false, "", "", nil
}
