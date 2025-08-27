// Copyright (c) 2025-present deep.rent GmbH (https://www.deep.rent)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package auth contains the rule model and authorizer used by the middleware.
// It compiles expr expressions and evaluates ordered rules to decide whether
// a request is allowed and which CouchDB user/roles to forward.
package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
)

// Guard compiles and evaluates authorization rules.
type Guard struct {
	rules []CompiledRule
}

// NewGuard compiles the provided rules.
func NewGuard(rules []Rule) (*Guard, error) {
	if len(rules) == 0 {
		return nil, errors.New("at least one rule is required")
	}
	compiled, err := NewCompiler().Compile(rules)
	if err != nil {
		return nil, err
	}
	return &Guard{rules: compiled}, nil
}

// Authorize evaluates rules in order and returns whether access is granted,
// and if so, the username and roles to forward to CouchDB. If no rule
// matches, access is denied.
func (g *Guard) Authorize(
	ctx context.Context,
	env Environment,
) (bool, string, string, error) {
	for _, rule := range g.rules {
		w, err := expr.Run(rule.when, env)
		if err != nil {
			return false, "", "", fmt.Errorf("eval when: %w", err)
		}
		pass, ok := w.(bool)
		if !ok {
			return false, "", "", fmt.Errorf("when must evaluate to bool, got %T", w)
		}
		if !pass {
			continue
		}

		if rule.mode == ModeDeny {
			return false, "", "", nil
		}

		u, err := expr.Run(rule.userName, env)
		if err != nil {
			return false, "", "", fmt.Errorf("eval userName: %w", err)
		}
		userName, ok := u.(string)
		if !ok {
			return false, "", "", fmt.Errorf("userName must evaluate to string, got %T", u)
		}

		r, err := expr.Run(rule.roles, env)
		if err != nil {
			return false, "", "", fmt.Errorf("eval roles: %w", err)
		}
		var roles string
		switch v := r.(type) {
		case string:
			roles = v
		case []string:
			roles = strings.Join(v, ",")
		case []any:
			items := make([]string, len(v))
			for i, e := range v {
				if s, ok := e.(string); ok {
					items[i] = s
				} else {
					return false, "", "", fmt.Errorf("roles must be string or []string; element at %d is %T", i, e)
				}
			}
			roles = strings.Join(items, ",")
		default:
			return false, "", "", fmt.Errorf("roles must evaluate to string or []string, got %T", r)
		}

		return true, userName, roles, nil
	}
	return false, "", "", nil
}
