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
	"errors"
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
func (g *Guard) Authorize(env Environment) (
	pass bool, user string, role string, err error,
) {
	for _, rule := range g.rules {
		skip, deny, u, r, e := rule.Evaluate(env)
		if e != nil {
			err = e
			return
		}
		if skip {
			continue
		}
		if deny {
			return
		}
		pass = true
		user = u
		role = r
		return
	}
	return
}
