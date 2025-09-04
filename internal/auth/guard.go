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
type Guard struct {
	parser *token.Parser
	engine *rules.Engine
}

// NewGuard constructs a Guard from configuration by wiring a token parser and
// compiling the authorization rules.
func NewGuard(ctx context.Context, cfg config.Config) (*Guard, error) {
	parser, err := token.NewParser(ctx, cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("create parser: %w", err)
	}
	engine, err := rules.NewEngine(cfg.Rules)
	if err != nil {
		return nil, fmt.Errorf("create engine: %w", err)
	}
	return &Guard{
		parser: parser,
		engine: engine,
	}, nil
}

// Check parses and validates the Bearer token from req, evaluates the rules,
// and returns the target CouchDB user/roles on success. It returns:
//
//   - token.ErrMissingToken or token.ErrInvalidToken if authentication fails.
//   - ErrForbidden when the request does not pass authorization.
//   - Other errors may be returned from the key provider lookup.
func (g *Guard) Check(req *http.Request) (scope Scope, err error) {
	// Parse and validate the access token from the Authorization header.
	tok, err := g.parser.Parse(req)
	if err != nil {
		return
	}
	// Build the rule evaluation environment and run the engine.
	env := rules.NewEnvironment(tok, req)
	res, err := g.engine.Eval(env)
	if err != nil {
		return
	}
	// Denied explicitly or implicitly (no rule matched).
	if !res.Pass {
		err = ErrForbidden
		return
	}
	// Access has been granted.
	scope = Scope{
		User:  res.User,
		Roles: res.Roles,
	}
	return
}
