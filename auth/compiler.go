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

package auth

import (
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// CompiledRule represents an authorization rule whose expressions have
// been compiled into executable programs.
type CompiledRule struct {
	mode     string
	when     *vm.Program
	userName *vm.Program
	roles    *vm.Program
}

// Compiler encapsulates rule compilation details.
type Compiler struct {
	opts []expr.Option
}

// NewCompiler creates a new instance of Compiler.
func NewCompiler() *Compiler {
	return &Compiler{opts: []expr.Option{expr.Env(Environment{})}}
}

// Compile compiles the provided rules into a set of executable programs.
func (c *Compiler) Compile(rules []Rule) ([]CompiledRule, error) {
	out := make([]CompiledRule, 0, len(rules))
	for i, rr := range rules {
		cr, err := c.compile(i, rr)
		if err != nil {
			return nil, err
		}
		out = append(out, cr)
	}
	return out, nil
}

// compile compiles a single authorization rule.
func (c *Compiler) compile(i int, r Rule) (CompiledRule, error) {
	mode := strings.ToLower(strings.TrimSpace(r.Mode))
	if mode != ModeAllow && mode != ModeDeny {
		return CompiledRule{}, fmt.Errorf(
			"rules[%d].mode must be '%s' or '%s'",
			i, ModeAllow, ModeDeny,
		)
	}

	w := strings.TrimSpace(r.When)
	if w == "" {
		return CompiledRule{}, fmt.Errorf(
			"rules[%d].when is required", i,
		)
	}
	when, err := expr.Compile(w, c.opts...)
	if err != nil {
		return CompiledRule{}, fmt.Errorf(
			"compile rules[%d].when: %w", i, err,
		)
	}

	var userName, roles *vm.Program
	if mode == ModeDeny {
		if strings.TrimSpace(r.UserName) != "" {
			return CompiledRule{}, fmt.Errorf(
				"rules[%d]: userName must not be set for %s mode",
				i, ModeDeny,
			)
		}
		if strings.TrimSpace(r.Roles) != "" {
			return CompiledRule{}, fmt.Errorf(
				"rules[%d]: roles must not be set for %s mode",
				i, ModeDeny,
			)
		}
	} else {
		u := strings.TrimSpace(r.UserName)
		if u == "" {
			return CompiledRule{}, fmt.Errorf(
				"rules[%d].user is required in %s mode",
				i, ModeAllow,
			)
		}
		userName, err = expr.Compile(u, c.opts...)
		if err != nil {
			return CompiledRule{}, fmt.Errorf(
				"compile rules[%d].userName: %w", i, err,
			)
		}
		r := strings.TrimSpace(r.Roles)
		if r == "" {
			r = "\"\""
		}
		roles, err = expr.Compile(r, c.opts...)
		if err != nil {
			return CompiledRule{}, fmt.Errorf(
				"compile rules[%d].roles: %w", i, err,
			)
		}
	}

	return CompiledRule{
		mode:     mode,
		when:     when,
		userName: userName,
		roles:    roles,
	}, nil
}
