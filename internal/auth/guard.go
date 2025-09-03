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
	"errors"
	"net/http"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/rules"
	"github.com/deep-rent/vouch/internal/token"
)

type Scope struct {
	User string
	Role string
}

var ErrForbidden = errors.New("insufficient permissions")

type Guard struct {
	parser *token.Parser
	engine *rules.Engine
}

func NewGuard(ctx context.Context, cfg config.Config) (*Guard, error) {
	parser, err := token.NewParser(ctx, cfg.Token)
	if err != nil {
		return nil, err
	}
	engine, err := rules.NewEngine(cfg.Rules)
	if err != nil {
		return nil, err
	}
	return &Guard{
		parser: parser,
		engine: engine,
	}, nil
}

func (g *Guard) Check(req *http.Request) (scope Scope, err error) {
	tok, err := g.parser.Parse(req)
	if err != nil {
		return
	}
	env := rules.NewEnvironment(tok, req)
	res, err := g.engine.Eval(env)
	if err != nil {
		return
	}
	if !res.Pass {
		err = ErrForbidden
		return
	}
	scope = Scope{
		User: res.User,
		Role: res.Role,
	}
	return
}
