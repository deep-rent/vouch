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

package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/expr-lang/expr"
)

// Authorizer compiles and evaluates authorization rules.
type Authorizer struct {
	rules []CompiledRule
}

// NewAuthorizer compiles the provided rules.
func NewAuthorizer(rules []Rule) (*Authorizer, error) {
	if len(rules) == 0 {
		return nil, errors.New("at least one rule is required")
	}
	compiled, err := NewCompiler().Compile(rules)
	if err != nil {
		return nil, err
	}
	return &Authorizer{rules: compiled}, nil
}

// Authorize evaluates rules in order and returns whether access is granted,
// and if so, the username and roles to forward to CouchDB. If no rule
// matches, access is denied.
func (a *Authorizer) Authorize(
	ctx context.Context,
	env Environment,
) (bool, string, string, error) {
	for _, r := range a.rules {
		whenRes, err := expr.Run(r.when, env)
		if err != nil {
			return false, "", "", fmt.Errorf("eval when: %w", err)
		}
		ok, isBool := whenRes.(bool)
		if !isBool {
			return false, "", "", fmt.Errorf("when must evaluate to bool, got %T", whenRes)
		}
		if !ok {
			continue
		}

		if r.mode == ModeDeny {
			return false, "", "", nil
		}

		userRes, err := expr.Run(r.user, env)
		if err != nil {
			return false, "", "", fmt.Errorf("eval user: %w", err)
		}
		user, isStr := userRes.(string)
		if !isStr || strings.TrimSpace(user) == "" {
			return false, "", "", fmt.Errorf("user must evaluate to non-empty string")
		}

		var role string
		if r.role != nil {
			val, err := expr.Run(r.role, env)
			if err != nil {
				return false, "", "", fmt.Errorf("eval role: %w", err)
			}
			switch v := val.(type) {
			case string:
				role = v
			case nil:
				role = ""
			default:
				return false, "", "", fmt.Errorf("role must evaluate to string, got %T", val)
			}
		}

		return true, user, role, nil
	}
	return false, "", "", nil
}
