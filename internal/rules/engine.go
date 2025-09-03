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

// Package rules defines an expression-based authorization model.
// It compiles human-readable rule definitions into executable programs and
// evaluates them against an evaluation environment in the request context.
package rules

import (
	"errors"

	"github.com/deep-rent/vouch/internal/config"
)

type Result struct {
	Pass bool
	User string
	Role string
}

// Engine evaluates authorization rules.
type Engine struct {
	rules []Rule
}

// NewEngine compiles the provided rules.
func NewEngine(rules []config.Rule) (*Engine, error) {
	if len(rules) == 0 {
		return nil, errors.New("at least one rule is required")
	}
	compiler := NewCompiler()
	compiled, err := compiler.Compile(rules)
	if err != nil {
		return nil, err
	}
	return &Engine{rules: compiled}, nil
}

// Eval evaluates rules in order and returns whether access is granted,
// and if so, the user and role(s) to forward to CouchDB. If no rule
// matches, access will be denied.
func (a *Engine) Eval(env Environment) (Result, error) {
	for _, r := range a.rules {
		skip, deny, user, role, err := r.Eval(env)
		if err != nil {
			return Result{}, err
		}
		if skip {
			continue
		}
		if deny {
			break
		}
		return Result{
			Pass: true,
			User: user,
			Role: role,
		}, nil
	}
	return Result{}, nil
}
