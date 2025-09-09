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
	"context"
	"fmt"
	"net/http"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/rules"
	"github.com/deep-rent/vouch/internal/token"
)

// AuthorizationError indicates that the request is authenticated but not
// authorized to proceed.
type AuthorizationError struct {
	msg string // human-readable error text
}

// Error implements the error interface.
func (e *AuthorizationError) Error() string {
	return e.msg
}

// ErrForbidden indicates that the request is authenticated but does not
// satisfy any allow rule (either no rule matched, or a deny rule matched).
var ErrForbidden = &AuthorizationError{msg: "insufficient permissions"}

// Guard validates incoming HTTP requests by parsing a Bearer token and
// evaluating authorization rules to determine the CouchDB user/roles to apply.
type Guard interface {
	// Check parses and validates the Bearer token from req, evaluates the rules,
	// and returns the target CouchDB user/roles on success. It returns:
	//
	//   - token.ErrMissingToken or token.ErrInvalidToken if authentication fails.
	//   - ErrForbidden when the request does not pass authorization.
	//   - Other errors may be returned from the key provider lookup.
	Check(req *http.Request) (rules.Scope, error)
}

// GuardFunc is an adapter to allow the use of ordinary functions as Guards.
type GuardFunc func(req *http.Request) (rules.Scope, error)

// Check implements the Guard interface.
func (f GuardFunc) Check(req *http.Request) (rules.Scope, error) {
	return f(req)
}

// guard is the default Guard implementation.
type guard struct {
	parser token.Parser
	engine rules.Engine
}

// Check parses and validates the Bearer token from req, evaluates the rules,
// and returns the target CouchDB user/roles on success. It returns:
//
//   - token.ErrMissingToken or token.ErrInvalidToken if authentication fails.
//   - ErrForbidden when the request does not pass authorization.
//   - Other errors may be returned from the key provider lookup.
func (g *guard) Check(req *http.Request) (rules.Scope, error) {
	// Parse and validate the access token from the Authorization header.
	tok, err := g.parser.Parse(req)
	if err != nil {
		return rules.Scope{}, err
	}
	// Build the rule evaluation environment and run the engine.
	env := rules.NewEnvironment(tok, req)
	res, err := g.engine.Eval(env)
	if err != nil {
		return rules.Scope{}, err
	}
	// Denied explicitly or implicitly (no rule matched).
	if !res.Allow {
		return rules.Scope{}, ErrForbidden
	}
	// Access has been granted.
	return res.Scope, nil
}

// Ensure guard satisfies the Guard contract.
var _ Guard = (*guard)(nil)

// Option for constructing a Guard without global seams.
type Option func(*options)

// options holds optional dependencies for constructing a Guard.
type options struct {
	parserFactory func(context.Context, config.Token) (token.Parser, error)
	engineFactory func([]config.Rule) (rules.Engine, error)
}

// WithParserFactory overrides how the token parser is constructed.
func WithParserFactory(
	f func(context.Context, config.Token) (token.Parser, error),
) Option {
	return func(o *options) { o.parserFactory = f }
}

// WithEngineFactory overrides how the rules engine is constructed.
func WithEngineFactory(f func([]config.Rule) (rules.Engine, error)) Option {
	return func(o *options) { o.engineFactory = f }
}

// WithParser injects a concrete token.Parser.
func WithParser(p token.Parser) Option {
	return WithParserFactory(
		func(context.Context, config.Token) (token.Parser, error) {
			return p, nil
		},
	)
}

// WithEngine injects a concrete rules.Engine.
func WithEngine(e rules.Engine) Option {
	return WithEngineFactory(
		func([]config.Rule) (rules.Engine, error) {
			return e, nil
		},
	)
}

// NewGuard constructs a Guard from configuration by wiring a token parser and
// compiling the authorization rules. Optional constructor options let tests
// inject dependencies without global seams.
func NewGuard(
	ctx context.Context,
	cfg config.Guard,
	opts ...Option,
) (Guard, error) {
	o := options{
		parserFactory: token.NewParser,
		engineFactory: rules.Compile,
	}
	for _, opt := range opts {
		opt(&o)
	}
	parser, err := o.parserFactory(ctx, cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("create parser: %w", err)
	}
	engine, err := o.engineFactory(cfg.Rules)
	if err != nil {
		return nil, fmt.Errorf("create engine: %w", err)
	}
	return NewGuardWithParserAndEngine(parser, engine), nil
}

// NewGuardWithParserAndEngine constructs a Guard from the provided token
// parser and rules engine. It is useful for testing.
func NewGuardWithParserAndEngine(
	parser token.Parser,
	engine rules.Engine,
) Guard {
	return &guard{parser: parser, engine: engine}
}
