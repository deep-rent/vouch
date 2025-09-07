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
	// Pass indicates whether access is granted.
	Pass bool
	// User is the CouchDB user name to authenticate as when Pass is true.
	User string
	// Roles is a comma-separated list of CouchDB roles when Pass is true.
	Roles string
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
}

// EngineFunc is an adapter to allow the use of ordinary functions as Engines.
type EngineFunc func(env Environment) (Result, error)

// Eval implements the Engine interface.
func (f EngineFunc) Eval(env Environment) (Result, error) {
	return f(env)
}

// engine is the default Engine implementation.
type engine struct {
	rules []rule
}

func (a *engine) Eval(env Environment) (Result, error) {
	for _, r := range a.rules {
		o, err := r.Eval(env)
		if err != nil {
			return Result{}, err
		}
		if o.Skip {
			continue
		}
		if o.Deny {
			// A deny rule matched, so we stop and deny access.
			return Result{Pass: false}, nil
		}
		// An allow rule matched.
		return Result{
			Pass:  true,
			User:  o.User,
			Roles: o.Roles,
		}, nil
	}
	// No rule matched, so we deny by default.
	return Result{Pass: false}, nil
}

// Ensure engine satisfies the Engine contract.
var _ Engine = (*engine)(nil)

// NewEngine compiles the provided declarative rules and returns an Engine.
// The given slice must not be empty.
func NewEngine(rules []config.Rule) (Engine, error) {
	if len(rules) == 0 {
		return nil, errors.New("at least one rule is required")
	}
	compiler := NewCompiler()
	compiled, err := compiler.Compile(rules)
	if err != nil {
		return nil, err
	}
	return &engine{rules: compiled}, nil
}
