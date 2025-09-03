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

// Mode defines the behavior of a rule when matched.
const (
	// ModeAllow grants access, authenticating the request on behalf of the
	// specified user.
	ModeAllow = "allow"
	// ModeDeny implies that access should be denied, preventing the
	// request from proceeding.
	ModeDeny = "deny"
)

// Rule represents an authorization rule whose expressions have been
// compiled into executable programs.
type Rule struct {
	deny  bool
	when  *vm.Program // required; evaluates to bool
	user  *vm.Program // optional; evaluates to string
	roles *vm.Program // optional; evaluates to []any
}

// evalWhen checks if the rule's condition is met.
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

// evalUser returns the CouchDB user to authenticate as, or an empty string
// to forward the request anonymously.
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

// evalRoles returns the CouchDB roles for authentication as a comma-joined
// string, or an empty string if no roles must be assigned.
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

// Eval executes the compiled expressions of this rule against the given
// environment.
func (r *Rule) Eval(env Environment) (
	skip bool, // whether this rule should be applied or skipped
	deny bool, // whether this rule grants or denies access (if not skipped)
	user string, // the CouchDB user to authenticate as (if not denied)
	roles string, // the CouchDB role(s) to authenticate with (if not denied)
	err error, // any error that occurred during evaluation
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

// Compiler encapsulates rule compilation details.
type Compiler struct {
	when  []expr.Option
	user  []expr.Option
	roles []expr.Option
}

// NewCompiler creates a new rule compiler.
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

// Compile compiles the rule definitions into a set of executable programs.
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

// compile compiles a single authorization rule.
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
