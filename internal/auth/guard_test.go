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

package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/rules"
	"github.com/deep-rent/vouch/internal/token"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockParser struct {
	fn func(*http.Request) (jwt.Token, error)
}

func (m mockParser) Parse(req *http.Request) (jwt.Token, error) {
	return m.fn(req)
}

type mockEngine struct {
	fn func(rules.Environment) (rules.Result, error)
	rs []rules.Rule
}

func (m mockEngine) Eval(env rules.Environment) (rules.Result, error) {
	if m.fn != nil {
		return m.fn(env)
	}
	return rules.Result{}, nil
}

func (m mockEngine) Rules() []rules.Rule { return m.rs }

func TestGuardCheck(t *testing.T) {
	makeToken := func(t *testing.T) jwt.Token {
		tok, err := jwt.NewBuilder().Subject("sub").Build()
		require.NoError(t, err)
		return tok
	}

	type test struct {
		name      string
		parser    token.Parser
		engine    rules.Engine
		wantScope rules.Scope
		wantErr   error
	}

	tests := []test{
		{
			name: "missing token",
			parser: mockParser{
				fn: func(*http.Request) (jwt.Token, error) {
					return nil, token.ErrMissingToken
				},
			},
			engine: mockEngine{
				fn: func(rules.Environment) (rules.Result, error) {
					return rules.Result{}, nil
				},
			},
			wantErr: token.ErrMissingToken,
		},
		{
			name: "invalid token",
			parser: mockParser{
				fn: func(*http.Request) (jwt.Token, error) {
					return nil, token.ErrInvalidToken
				},
			},
			engine: mockEngine{
				fn: func(rules.Environment) (rules.Result, error) {
					return rules.Result{}, nil
				},
			},
			wantErr: token.ErrInvalidToken,
		},
		{
			name: "engine error",
			parser: mockParser{
				fn: func(*http.Request) (jwt.Token, error) {
					return makeToken(t), nil
				},
			},
			engine: mockEngine{
				fn: func(rules.Environment) (rules.Result, error) {
					return rules.Result{}, assert.AnError
				},
			},
			wantErr: assert.AnError,
		},
		{
			name: "forbidden",
			parser: mockParser{
				fn: func(*http.Request) (jwt.Token, error) {
					return makeToken(t), nil
				},
			},
			engine: mockEngine{
				fn: func(rules.Environment) (rules.Result, error) {
					return rules.Result{Allow: false}, nil
				},
			},
			wantErr: auth.ErrForbidden,
		},
		{
			name: "allow with user and roles",
			parser: mockParser{
				fn: func(*http.Request) (jwt.Token, error) {
					return makeToken(t), nil
				},
			},
			engine: mockEngine{
				fn: func(rules.Environment) (rules.Result, error) {
					return rules.Result{
						Allow: true,
						Scope: rules.Scope{User: "alice", Roles: "r1,r2"},
					}, nil
				},
			},
			wantScope: rules.Scope{User: "alice", Roles: "r1,r2"},
		},
		{
			name: "allow anonymous",
			parser: mockParser{
				fn: func(*http.Request) (jwt.Token, error) { return makeToken(t), nil },
			},
			engine: mockEngine{
				fn: func(rules.Environment) (rules.Result, error) {
					return rules.Result{Allow: true}, nil
				},
			},
			wantScope: rules.Scope{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, err := auth.NewGuard(
				t.Context(),
				config.Guard{},
				auth.WithParser(tc.parser),
				auth.WithEngine(tc.engine),
			)
			require.NoError(t, err)

			req := httptest.NewRequest(
				http.MethodGet,
				"http://example/db/doc",
				nil,
			)
			scope, err := g.Check(req)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantScope, scope)
		})
	}
}

func TestNewGuard(t *testing.T) {
	t.Run("parser error", func(t *testing.T) {
		_, err := auth.NewGuard(
			t.Context(),
			config.Guard{},
			auth.WithParserFactory(
				func(context.Context, config.Token) (token.Parser, error) {
					return nil, assert.AnError
				},
			),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create parser")
	})

	t.Run("engine error", func(t *testing.T) {
		_, err := auth.NewGuard(
			t.Context(),
			config.Guard{},
			auth.WithParserFactory(
				func(context.Context, config.Token) (token.Parser, error) {
					return mockParser{
						fn: func(*http.Request) (jwt.Token, error) {
							return nil, assert.AnError
						},
					}, nil
				},
			),
			auth.WithEngineFactory(func([]config.Rule) (rules.Engine, error) {
				return nil, assert.AnError
			}),
		)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create engine")
	})

	t.Run("success", func(t *testing.T) {
		g, err := auth.NewGuard(
			t.Context(),
			config.Guard{Rules: []config.Rule{{When: "true"}}},
			auth.WithParser(
				mockParser{fn: func(*http.Request) (jwt.Token, error) {
					return jwt.NewBuilder().Build()
				}},
			),
			auth.WithEngine(
				mockEngine{fn: func(rules.Environment) (rules.Result, error) {
					return rules.Result{Allow: true}, nil
				}},
			),
		)
		require.NoError(t, err)
		require.NotNil(t, g)
	})
}
