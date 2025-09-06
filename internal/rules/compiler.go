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
func (c *Compiler) Compile(rules []config.Rule) ([]rule, error) {
	out := make([]rule, 0, len(rules))
	for i, r := range rules {
		compiled, err := c.compile(r)
		if err != nil {
			return nil, fmt.Errorf("compile rules[%d].%w", i, err)
		}
		out = append(out, compiled)
	}
	return out, nil
}

// compile compiles a single rule and validates its shape based on mode.
// For deny rules, user and roles must not be provided; for allow rules,
// when is required and user/roles are optional.
func (c *Compiler) compile(r config.Rule) (rule, error) {
	when, err := expr.Compile(r.When, c.when...)
	if err != nil {
		return rule{}, fmt.Errorf("when: %w", err)
	}

	deny := r.Deny
	var user, roles *vm.Program
	if !deny {
		if u := r.User; u != "" {
			var err error
			user, err = expr.Compile(u, c.user...)
			if err != nil {
				return rule{}, fmt.Errorf("user: %w", err)
			}
		}
		if r := r.Roles; r != "" {
			var err error
			roles, err = expr.Compile(r, c.roles...)
			if err != nil {
				return rule{}, fmt.Errorf("roles: %w", err)
			}
		}
	}

	return rule{
		deny:  deny,
		when:  when,
		user:  user,
		roles: roles,
	}, nil
}
