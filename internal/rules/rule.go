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

package rules

import (
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

type Scope struct {
	// User is the CouchDB user name to authenticate as.
	User string
	// Roles is a comma-separated list of CouchDB roles.
	Roles string
}

// IsAnonymous returns true if the scope does not specify a user.
func (s Scope) IsAnonymous() bool {
	return s.User == ""
}

// func (s Scope) String() string {
// 	if s.IsAnonymous() {
// 		return "<anonymous>"
// 	}
// 	return fmt.Sprintf("%s[%s]", s.User, s.Roles)
// }

// Rule is a compiled authorization Rule.
// Its expressions are compiled once and evaluated for each request against an
// Environment. When the Rule matches, it either denies the request or
// provides authentication parameters (user and roles).
type Rule struct {
	Deny  bool        // whether the rule denies access when matched
	When  *vm.Program // required; evaluates to bool
	User  *vm.Program // optional; evaluates to string
	Roles *vm.Program // optional; evaluates to []any of strings
}

// Action holds the result of evaluating a single rule.
// It indicates what to do next in the evaluation process.
type Action struct {
	// Skip is true if the rule's condition did not match.
	// It indicates that the rule should be ignored.
	Skip bool
	// Deny is true if the rule matched and is a "deny" rule.
	// It indicates that access should be denied immediately.
	Deny bool
	// Grant is the scope to assign both Skip and Deny are false.
	// It indicates that access is granted.
	Grant Scope
}

// EvalWhen evaluates the rule's "when" condition against the environment and
// reports whether the rule matches.
func (r *Rule) EvalWhen(env Environment) (bool, error) {
	v, err := expr.Run(r.When, env)
	if err != nil {
		return false, fmt.Errorf("eval when: %w", err)
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("when must return bool, got %T", v)
	}
	return b, nil
}

// EvalUser evaluates the "user" expression and returns the CouchDB user name
// to authenticate as. It returns an empty string when no user is configured.
func (r *Rule) EvalUser(env Environment) (string, error) {
	if r.User == nil {
		return "", nil
	}
	v, err := expr.Run(r.User, env)
	if err != nil {
		return "", fmt.Errorf("eval user: %w", err)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("user must return to string, got %T", v)
	}
	return s, nil
}

// EvalRoles evaluates the "roles" expression and returns a comma-joined list
// of CouchDB roles to be assigned to the user. It returns an empty string
// when no roles are configured.
func (r *Rule) EvalRoles(env Environment) (string, error) {
	if r.Roles == nil {
		return "", nil
	}
	v, err := expr.Run(r.Roles, env)
	if err != nil {
		return "", fmt.Errorf("eval roles: %w", err)
	}
	a, ok := v.([]any)
	if !ok {
		return "", fmt.Errorf("roles must produce a slice, got %T", v)
	}
	b := make([]string, len(a))
	for i, e := range a {
		s, ok := e.(string)
		if !ok {
			return "", fmt.Errorf("roles[%d] must be string, was %T", i, e)
		}
		b[i] = s
	}
	return strings.Join(b, ","), nil
}

// Eval evaluates the rule against the specified environment.
// It returns a result struct describing the outcome or an error if the
// evaluation of any expression fails.
func (r *Rule) Eval(env Environment) (Action, error) {
	pass, err := r.EvalWhen(env)
	if err != nil {
		return Action{}, err
	}
	if !pass {
		return Action{Skip: true}, nil
	}
	if r.Deny {
		return Action{Deny: true}, nil
	}

	user, err := r.EvalUser(env)
	if err != nil {
		return Action{}, err
	}

	roles, err := r.EvalRoles(env)
	if err != nil {
		return Action{}, err
	}

	s := Scope{User: user, Roles: roles}
	return Action{Grant: s}, nil
}
