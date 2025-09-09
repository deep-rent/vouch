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
	"errors"

	"github.com/deep-rent/vouch/internal/config"
)

// Result captures the outcome of evaluating rules for a request.
type Result struct {
	// Allow indicates whether access is granted.
	// If false, the caller should immediately reject the request.
	Allow bool
	// Scope is the authorization scope to grant if Allow is true.
	// If Allow is false, Scope is zero-valued.
	Scope Scope
}

// Engine evaluates a list of authorization rules in order.
type Engine interface {
	// Eval scans rules in order and returns the first allow decision alongside
	// the user and role(s) to forward to CouchDB. If a deny rule matches, access
	// is denied immediately. If no rule matches, access is denied by default.
	//
	// On denial (explicit or implicit), a zero-value Result and nil error are
	// returned so the caller can decide how to respond upstream.
	Eval(env Environment) (Result, error)
	// Rules returns the compiled rules used by the engine.
	Rules() []Rule
}

// engine is the default Engine implementation.
type engine struct {
	rules []Rule
}

func (e *engine) Eval(env Environment) (Result, error) {
	for _, r := range e.rules {
		a, err := r.Eval(env)
		if err != nil {
			return Result{}, err
		}
		if a.Skip {
			continue
		}
		if a.Deny {
			// A deny rule matched, so we stop and deny access.
			return Result{}, nil
		}
		// An allow rule matched.
		res := Result{Allow: true, Scope: a.Grant}
		return res, nil
	}
	// No rule matched, so we deny by default.
	return Result{}, nil
}

func (e *engine) Rules() []Rule {
	return e.rules
}

// Ensure engine satisfies the Engine contract.
var _ Engine = (*engine)(nil)

// Compile compiles the provided declarative rules and returns an Engine.
// The given slice must not be empty.
func Compile(rules []config.Rule) (Engine, error) {
	compiler := NewCompiler()
	compiled, err := compiler.Compile(rules)
	if err != nil {
		return nil, err
	}
	return NewEngine(compiled)
}

// NewEngine constructs an Engine from pre-compiled rules.
func NewEngine(rules []Rule) (Engine, error) {
	if len(rules) == 0 {
		return nil, errors.New("at least one rule is required")
	}
	return &engine{rules: rules}, nil
}
