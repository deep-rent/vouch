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

// Mode enumerates the decision a rule applies when its condition is met.
// A rule either allows (optionally authenticating as a user) or denies
// the incoming request.
const (
	// ModeAllow grants access and may authenticate the request on behalf of
	// the specified user with optional roles.
	ModeAllow = "allow"
	// ModeDeny denies access and prevents the request from proceeding.
	ModeDeny = "deny"
)

// Rule is a compiled authorization rule.
// Its expressions are compiled once and evaluated for each request against an
// Environment. When the rule matches, it either denies the request or
// provides authentication parameters (user and roles).
type Rule struct {
	deny  bool        // whether the rule denies access when matched
	when  *vm.Program // required; evaluates to bool
	user  *vm.Program // optional; evaluates to string
	roles *vm.Program // optional; evaluates to []any of strings
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

// Eval evaluates the rule against the specified environment and returns:
//   - skip: whether the rule did not match and should be ignored.
//   - deny: whether access is denied (only meaningful when not skipped).
//   - user: CouchDB username to authenticate as (if neither skipped nor denied).
//   - roles: comma-separated CouchDB roles (if neither skipped nor denied).
//   - err: any error that occurred during evaluation.
//
// If any evaluation error occurs, it is returned and evaluation stops.
func (r *Rule) Eval(env Environment) (
	skip bool,
	deny bool,
	user string,
	roles string,
	err error,
) {
	pass, err := r.evalWhen(env)
	if err != nil {
		return
	}
	if !pass {
		skip = true
		return
	}
	if r.deny {
		deny = true
		return
	}
	user, err = r.evalUser(env)
	if err != nil {
		return
	}
	roles, err = r.evalRoles(env)
	if err != nil {
		user = ""
		return
	}
	return
}
