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

// Rule is a compiled authorization Rule.
// Its expressions are compiled once and evaluated for each request against an
// Environment. When the Rule matches, it either denies the request or
// provides authentication parameters (user and roles).
type Rule struct {
	deny  bool        // whether the rule denies access when matched
	when  *vm.Program // required; evaluates to bool
	user  *vm.Program // optional; evaluates to string
	roles *vm.Program // optional; evaluates to []any of strings
}

// result holds the result of evaluating a single rule.
type result struct {
	// Skip is true if the rule's condition did not match.
	Skip bool
	// Deny is true if the rule matched and is a "deny" rule.
	Deny bool
	// User is the CouchDB user name to authenticate as.
	User string
	// Roles is a comma-separated list of CouchDB roles.
	Roles string
}

// evalWhen evaluates the rule's "when" condition against the environment and
// reports whether the rule matches.
func (r *Rule) evalWhen(env Environment) (bool, error) {
	v, err := expr.Run(r.when, env)
	if err != nil {
		return false, fmt.Errorf("eval when: %w", err)
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("when must return bool, got %T", v)
	}
	return b, nil
}

// evalUser evaluates the "user" expression and returns the CouchDB user name
// to authenticate as. It returns an empty string when no user is configured.
func (r *Rule) evalUser(env Environment) (string, error) {
	if r.user == nil {
		return "", nil
	}
	v, err := expr.Run(r.user, env)
	if err != nil {
		return "", fmt.Errorf("eval user: %w", err)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("user must return to string, got %T", v)
	}
	return s, nil
}

// evalRoles evaluates the "roles" expression and returns a comma-joined list
// of CouchDB roles to be assigned to the user. It returns an empty string
// when no roles are configured.
func (r *Rule) evalRoles(env Environment) (string, error) {
	if r.roles == nil {
		return "", nil
	}
	v, err := expr.Run(r.roles, env)
	if err != nil {
		return "", fmt.Errorf("eval roles: %w", err)
	}
	a, ok := v.([]any)
	if !ok {
		return "", fmt.Errorf("roles must produce a slice, got %T", v)
	}
	b := make([]string, len(a))
	for i, e := range a {
		if s, ok := e.(string); !ok {
			return "", fmt.Errorf("roles[%d] must be string, was %T", i, e)
		} else {
			b[i] = s
		}
	}
	return strings.Join(b, ","), nil
}

// Eval evaluates the rule against the specified environment.
// It returns a result struct describing the outcome or an error if the
// evaluation of any expression fails.
func (r *Rule) Eval(env Environment) (result, error) {
	pass, err := r.evalWhen(env)
	if err != nil {
		return result{}, err
	}
	if !pass {
		return result{Skip: true}, nil
	}
	if r.deny {
		return result{Deny: true}, nil
	}

	user, err := r.evalUser(env)
	if err != nil {
		return result{}, err
	}

	roles, err := r.evalRoles(env)
	if err != nil {
		return result{}, err
	}

	return result{User: user, Roles: roles}, nil
}
