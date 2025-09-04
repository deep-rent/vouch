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
