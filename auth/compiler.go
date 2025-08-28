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
	mode string
	when *vm.Program
	user *vm.Program
	role *vm.Program
}

// evalWhen evaluates the compiled `when` program and returns a bool.
func (c *CompiledRule) evalWhen(env Environment) (bool, error) {
	v, err := expr.Run(c.when, env)
	if err != nil {
		return false, fmt.Errorf("eval when: %w", err)
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("when must evaluate to bool, got %T", v)
	}
	return b, nil
}

// evalUser evaluates the compiled `user` program and returns a string.
func (c *CompiledRule) evalUser(env Environment) (string, error) {
	v, err := expr.Run(c.user, env)
	if err != nil {
		return "", fmt.Errorf("eval user: %w", err)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("user must evaluate to string, got %T", v)
	}
	return s, nil
}

// evalRole evaluates the compiled `role` program and returns a comma-joined string.
func (c *CompiledRule) evalRole(env Environment) (string, error) {
	v, err := expr.Run(c.role, env)
	if err != nil {
		return "", fmt.Errorf("eval role: %w", err)
	}
	switch t := v.(type) {
	case string:
		return t, nil
	case []string:
		return strings.Join(t, ","), nil
	case []any:
		items := make([]string, len(t))
		for i, e := range t {
			s, ok := e.(string)
			if !ok {
				return "", fmt.Errorf("role at %d must be string, was %T", i, e)
			}
			items[i] = s
		}
		return strings.Join(items, ","), nil
	default:
		return "", fmt.Errorf("role must evaluate to string or []string, got %T", v)
	}
}

// Evaluate executes the compiled expressions for a rule against the provided
// environment.
func (c *CompiledRule) Evaluate(env Environment) (
	skip bool, deny bool, user string, role string, err error,
) {
	pass, err := c.evalWhen(env)
	if err != nil {
		return
	}
	if !pass {
		skip = true
		return
	}
	if c.mode == ModeDeny {
		deny = true
		return
	}
	user, err = c.evalUser(env)
	if err != nil {
		return
	}
	role, err = c.evalRole(env)
	if err != nil {
		user = ""
		return
	}
	return
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
	for i, r := range rules {
		compiled, err := c.compile(i, r)
		if err != nil {
			return nil, err
		}
		out = append(out, compiled)
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

	var user, role *vm.Program
	if mode == ModeDeny {
		if strings.TrimSpace(r.User) != "" {
			return CompiledRule{}, fmt.Errorf(
				"rules[%d]: user must not be set for %s mode",
				i, ModeDeny,
			)
		}
		if strings.TrimSpace(r.Role) != "" {
			return CompiledRule{}, fmt.Errorf(
				"rules[%d]: role must not be set for %s mode",
				i, ModeDeny,
			)
		}
	} else {
		u := strings.TrimSpace(r.User)
		if u == "" {
			return CompiledRule{}, fmt.Errorf(
				"rules[%d].user is required in %s mode",
				i, ModeAllow,
			)
		}
		user, err = expr.Compile(u, c.opts...)
		if err != nil {
			return CompiledRule{}, fmt.Errorf(
				"compile rules[%d].user: %w", i, err,
			)
		}
		r := strings.TrimSpace(r.Role)
		if r == "" {
			r = "\"\""
		}
		role, err = expr.Compile(r, c.opts...)
		if err != nil {
			return CompiledRule{}, fmt.Errorf(
				"compile rules[%d].role: %w", i, err,
			)
		}
	}

	return CompiledRule{
		mode: mode,
		when: when,
		user: user,
		role: role,
	}, nil
}
