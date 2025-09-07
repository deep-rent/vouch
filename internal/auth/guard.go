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

// Scope encapsulates the authentication parameters to forward to CouchDB via
// the proxy headers. It defines the access scope granted to the request.
type Scope struct {
	// User is the CouchDB user name to authenticate as.
	User string
	// Roles is a comma-separated list of CouchDB roles.
	Roles string
}

// IsAnonymous returns true if the scope does not specify a user.
func (s Scope) IsAnonymous() bool {
	return s.User == ""
}

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
	Check(req *http.Request) (Scope, error)
}

// GuardFunc is an adapter to allow the use of ordinary functions as Guards.
type GuardFunc func(req *http.Request) (Scope, error)

// Check implements the Guard interface.
func (f GuardFunc) Check(req *http.Request) (Scope, error) {
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
func (g *guard) Check(req *http.Request) (Scope, error) {
	// Parse and validate the access token from the Authorization header.
	tok, err := g.parser.Parse(req)
	if err != nil {
		return Scope{}, err
	}
	// Build the rule evaluation environment and run the engine.
	env := rules.NewEnvironment(tok, req)
	res, err := g.engine.Eval(env)
	if err != nil {
		return Scope{}, err
	}
	// Denied explicitly or implicitly (no rule matched).
	if !res.Pass {
		return Scope{}, ErrForbidden
	}
	// Access has been granted.
	return Scope{
		User:  res.User,
		Roles: res.Roles,
	}, nil
}

// Ensure guard satisfies the Guard contract.
var _ Guard = (*guard)(nil)

// seams (overridable in tests)
var (
	newParser = token.NewParser
	newEngine = rules.NewEngine
)

// NewGuard constructs a Guard from configuration by wiring a token parser and
// compiling the authorization rules.
func NewGuard(ctx context.Context, cfg config.Config) (Guard, error) {
	parser, err := newParser(ctx, cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("create parser: %w", err)
	}
	engine, err := newEngine(cfg.Rules)
	if err != nil {
		return nil, fmt.Errorf("create engine: %w", err)
	}
	return &guard{
		parser: parser,
		engine: engine,
	}, nil
}
