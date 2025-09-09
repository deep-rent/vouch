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

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/rules"
	"github.com/deep-rent/vouch/internal/token"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeIsAnonymous(t *testing.T) {
	assert.True(t, (Scope{}).IsAnonymous())
	assert.False(t, (Scope{User: "u"}).IsAnonymous())
}

func TestGuardCheck(t *testing.T) {
	makeToken := func(t *testing.T) jwt.Token {
		tok, err := jwt.NewBuilder().Subject("sub").Build()
		require.NoError(t, err)
		return tok
	}

	type test struct {
		// inputs
		name   string
		parser token.Parser
		engine rules.Engine
		// expected outputs
		scope Scope
		err   error
	}

	tests := []test{
		{
			name:   "missing token",
			parser: token.ParserFunc(func(*http.Request) (jwt.Token, error) { return nil, token.ErrMissingToken }),
			engine: rules.EngineFunc(func(rules.Environment) (rules.Result, error) { return rules.Result{}, nil }),
			err:    token.ErrMissingToken,
		},
		{
			name:   "invalid token",
			parser: token.ParserFunc(func(*http.Request) (jwt.Token, error) { return nil, token.ErrInvalidToken }),
			engine: rules.EngineFunc(func(rules.Environment) (rules.Result, error) { return rules.Result{}, nil }),
			err:    token.ErrInvalidToken,
		},
		{
			name: "engine error",
			parser: token.ParserFunc(func(*http.Request) (jwt.Token, error) {
				return makeToken(t), nil
			}),
			engine: rules.EngineFunc(func(rules.Environment) (rules.Result, error) { return rules.Result{}, assert.AnError }),
			err:    assert.AnError,
		},
		{
			name: "forbidden",
			parser: token.ParserFunc(func(*http.Request) (jwt.Token, error) {
				return makeToken(t), nil
			}),
			engine: rules.EngineFunc(func(rules.Environment) (rules.Result, error) { return rules.Result{Pass: false}, nil }),
			err:    ErrForbidden,
		},
		{
			name: "allow with user and roles",
			parser: token.ParserFunc(func(*http.Request) (jwt.Token, error) {
				return makeToken(t), nil
			}),
			engine: rules.EngineFunc(func(rules.Environment) (rules.Result, error) {
				return rules.Result{Pass: true, User: "alice", Roles: "r1,r2"}, nil
			}),
			scope: Scope{User: "alice", Roles: "r1,r2"},
		},
		{
			name: "allow anonymous",
			parser: token.ParserFunc(func(*http.Request) (jwt.Token, error) {
				return makeToken(t), nil
			}),
			engine: rules.EngineFunc(func(rules.Environment) (rules.Result, error) {
				return rules.Result{Pass: true}, nil
			}),
			scope: Scope{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g := &guard{
				parser: tc.parser,
				engine: tc.engine,
			}
			req := httptest.NewRequest("GET", "http://example/db/doc", nil)
			scope, err := g.Check(req)

			if tc.err != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.scope, scope)
		})
	}
}

func TestNewGuard(t *testing.T) {
	oldParser := newParser
	oldEngine := newEngine

	t.Cleanup(func() {
		newParser = oldParser
		newEngine = oldEngine
	})

	t.Run("parser error", func(t *testing.T) {
		newParser = func(context.Context, config.Token) (token.Parser, error) {
			return nil, assert.AnError
		}
		_, err := NewGuard(context.Background(), config.Guard{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create parser")
	})

	t.Run("engine error", func(t *testing.T) {
		newParser = func(context.Context, config.Token) (token.Parser, error) {
			return token.ParserFunc(func(*http.Request) (jwt.Token, error) {
				return nil, nil
			}), nil
		}
		newEngine = func([]config.Rule) (rules.Engine, error) {
			return nil, assert.AnError
		}
		_, err := NewGuard(context.Background(), config.Guard{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "create engine")
	})

	t.Run("success", func(t *testing.T) {
		newParser = func(context.Context, config.Token) (token.Parser, error) {
			return token.ParserFunc(func(*http.Request) (jwt.Token, error) {
				return jwt.NewBuilder().Build()
			}), nil
		}
		newEngine = func([]config.Rule) (rules.Engine, error) {
			return rules.EngineFunc(func(rules.Environment) (rules.Result, error) {
				return rules.Result{Pass: true}, nil
			}), nil
		}
		g, err := NewGuard(context.Background(), config.Guard{
			Rules: []config.Rule{{When: "true"}},
		})
		require.NoError(t, err)
		require.NotNil(t, g)
	})
}

func TestGuardFunc(t *testing.T) {
	g := GuardFunc(func(*http.Request) (Scope, error) { return Scope{User: "u"}, nil })
	s, err := g.Check(httptest.NewRequest("GET", "/", nil))
	require.NoError(t, err)
	require.Equal(t, "u", s.User)
}
