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
	"reflect"
	"strings"

	"github.com/deep-rent/vouch/internal/config"
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

// Eval evaluates the rule against env and returns:
//   - skip: whether the rule did not match (when=false) and should be ignored.
//   - deny: whether access is denied (only meaningful when not skipped).
//   - user: CouchDB username to authenticate as (when allowed).
//   - roles: comma-separated CouchDB roles (when allowed).
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

// Compiler compiles declarative rule definitions into executable programs.
// It enforces result types for each expression (bool for when, string for user,
// and slice for roles) at compile time.
type Compiler struct {
	when  []expr.Option // compile options for "when" expressions
	user  []expr.Option // compile options for "user" expressions
	roles []expr.Option // compile options for "roles" expressions
}

// NewCompiler builds a compiler that type-checks expressions against the
// Environment and enables bytecode optimizations.
func NewCompiler() *Compiler {
	base := []expr.Option{
		expr.Env(Environment{}),
		expr.Optimize(true),
	}
	opts := func(add ...expr.Option) []expr.Option {
		out := make([]expr.Option, len(base)+len(add))
		copy(out, base)
		return append(out, add...)
	}
	return &Compiler{
		when:  opts(expr.AsBool()),
		user:  opts(expr.AsKind(reflect.String)),
		roles: opts(expr.AsKind(reflect.Slice)),
	}
}

// Compile compiles a slice of declarative rules into executable Rules.
// Rules are compiled in order and returned in the same order.
func (c *Compiler) Compile(rules []config.Rule) ([]Rule, error) {
	out := make([]Rule, 0, len(rules))
	for i, r := range rules {
		rule, err := c.compile(i, r)
		if err != nil {
			return nil, err
		}
		out = append(out, rule)
	}
	return out, nil
}

// compile compiles a single rule and validates its shape based on mode.
// For deny rules, user and roles must not be provided; for allow rules,
// when is required and user/roles are optional.
func (c *Compiler) compile(i int, rule config.Rule) (Rule, error) {
	mode := strings.ToLower(strings.TrimSpace(rule.Mode))
	deny := mode == ModeDeny
	if mode != ModeAllow && !deny {
		return Rule{}, fmt.Errorf(
			"rules[%d].mode must be '%s' or '%s'",
			i, ModeAllow, ModeDeny,
		)
	}

	var when *vm.Program
	{
		w := strings.TrimSpace(rule.When)
		if w == "" {
			return Rule{}, fmt.Errorf(
				"rules[%d].when is required", i,
			)
		}
		var err error
		when, err = expr.Compile(w, c.when...)
		if err != nil {
			return Rule{}, fmt.Errorf(
				"compile rules[%d].when: %w", i, err,
			)
		}
	}

	var user, roles *vm.Program
	if deny {
		// Deny mode: user and roles must not be set.
		if strings.TrimSpace(rule.User) != "" {
			return Rule{}, fmt.Errorf(
				"rules[%d].user must not be set for %s mode",
				i, ModeDeny,
			)
		}
		if strings.TrimSpace(rule.Roles) != "" {
			return Rule{}, fmt.Errorf(
				"rules[%d].roles must not be set for %s mode",
				i, ModeDeny,
			)
		}
	} else {
		// Allow mode: user and roles can be set.
		u := strings.TrimSpace(rule.User)
		if u != "" {
			var err error
			user, err = expr.Compile(u, c.user...)
			if err != nil {
				return Rule{}, fmt.Errorf(
					"compile rules[%d].user: %w", i, err,
				)
			}
		}
		r := strings.TrimSpace(rule.Roles)
		if r != "" {
			var err error
			roles, err = expr.Compile(r, c.roles...)
			if err != nil {
				return Rule{}, fmt.Errorf(
					"compile rules[%d].roles: %w", i, err,
				)
			}
		}
	}

	return Rule{
		deny:  deny,
		when:  when,
		user:  user,
		roles: roles,
	}, nil
}
