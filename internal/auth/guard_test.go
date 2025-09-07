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
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/vouch/internal/rules"
	"github.com/deep-rent/vouch/internal/token"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeIsAnonymous(t *testing.T) {
	assert.True(t, (Scope{}).IsAnonymous())
	assert.False(t, (Scope{User: "alice"}).IsAnonymous())
}

func TestGuardCheck(t *testing.T) {
	sentinel := errors.New("sentinel")

	tests := []struct {
		name      string
		parserErr error
		engineRes rules.Result
		engineErr error
		wantScope Scope
		wantErr   error
	}{
		{
			name:      "missing token",
			parserErr: token.ErrMissingToken,
			wantErr:   token.ErrMissingToken,
		},
		{
			name:      "invalid token",
			parserErr: token.ErrInvalidToken,
			wantErr:   token.ErrInvalidToken,
		},
		{
			name:      "parser other error",
			parserErr: sentinel,
			wantErr:   sentinel,
		},
		{
			name:      "engine error",
			engineErr: sentinel,
			wantErr:   sentinel,
		},
		{
			name:      "forbidden (pass false)",
			engineRes: rules.Result{Pass: false},
			wantErr:   ErrForbidden,
		},
		{
			name:      "allow with user and roles",
			engineRes: rules.Result{Pass: true, User: "alice", Roles: "r1,r2"},
			wantScope: Scope{User: "alice", Roles: "r1,r2"},
		},
		{
			name:      "allow anonymous",
			engineRes: rules.Result{Pass: true},
			wantScope: Scope{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var parserCalled bool
			var engineCalled bool

			// Mock parser
			p := token.ParserFunc(func(req *http.Request) (jwt.Token, error) {
				parserCalled = true
				if tc.parserErr != nil {
					return nil, tc.parserErr
				}
				tok, err := jwt.NewBuilder().Build()
				require.NoError(t, err)
				return tok, nil
			})

			// Mock engine
			e := rules.EngineFunc(func(env rules.Environment) (rules.Result, error) {
				engineCalled = true
				return tc.engineRes, tc.engineErr
			})

			g := &guard{parser: p, engine: e}

			req := httptest.NewRequest("GET", "http://example.org/db/doc", nil)
			scope, err := g.Check(req)

			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.wantScope, scope)
			if err == nil && tc.wantScope == (Scope{}) {
				assert.True(t, tc.engineRes.Pass) // Anonymous case
			}
			assert.True(t, parserCalled)
			if tc.parserErr == nil {
				assert.True(t, engineCalled)
			}
		})
	}
}
