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

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/logger"
	"github.com/deep-rent/vouch/internal/middleware"
	"github.com/deep-rent/vouch/internal/rules"
	"github.com/deep-rent/vouch/internal/token"
	"github.com/stretchr/testify/assert"
)

type mockGuard struct {
	scope rules.Scope
	err   error
}

func (g mockGuard) Check(*http.Request) (rules.Scope, error) {
	return g.scope, g.err
}

func TestForward(t *testing.T) {
	tests := []struct {
		name  string
		cfg   config.Headers
		scope rules.Scope
		err   error

		wantStatus    int
		wantUser      string
		wantRoles     string
		wantToken     string
		wantNext      bool
		wantChallenge bool
	}{
		{
			name: "authenticated with roles + secret (signed token)",
			cfg: config.Headers{
				User:  config.UserHeader{Name: "X-Test-User"},
				Roles: config.RolesHeader{Name: "X-Test-Roles"},
				Token: config.TokenHeader{
					Name:   "X-Test-Token",
					Signer: config.Signer{Secret: "secret"},
				},
			},
			scope: rules.Scope{User: "test", Roles: "foo,bar"},
			// Digest observed in existing dedicated test; keep deterministic assertion.
			wantToken:  "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914",
			wantStatus: http.StatusOK,
			wantUser:   "test",
			wantRoles:  "foo,bar",
			wantNext:   true,
		},
		{
			name: "authenticated no roles no secret",
			cfg: config.Headers{
				User:  config.UserHeader{Name: "X-Test-User", Anonymous: true},
				Roles: config.RolesHeader{Name: "X-Test-Roles"},
				Token: config.TokenHeader{
					Name:   "X-Test-Token",
					Signer: config.Signer{},
				},
			},
			scope:      rules.Scope{User: "user"},
			wantStatus: http.StatusOK,
			wantUser:   "user",
			wantRoles:  "",
			wantToken:  "",
			wantNext:   true,
		},
		{
			name: "anonymous allowed (secret present) => no auth headers injected",
			cfg: config.Headers{
				User:  config.UserHeader{Name: "X-Test-User", Anonymous: true},
				Roles: config.RolesHeader{Name: "X-Test-Roles"},
				Token: config.TokenHeader{
					Name:   "X-Test-Token",
					Signer: config.Signer{Secret: "secret"},
				},
			},
			scope:      rules.Scope{},
			wantStatus: http.StatusOK,
			wantUser:   "",
			wantRoles:  "",
			wantToken:  "",
			wantNext:   true,
		},
		{
			name: "anonymous rejected (not allowed)",
			cfg: config.Headers{
				User:  config.UserHeader{Name: "X-Test-User"},
				Roles: config.RolesHeader{Name: "X-Test-Roles"},
				Token: config.TokenHeader{Name: "X-Test-Token"},
			},
			scope:      rules.Scope{},
			wantStatus: http.StatusUnauthorized,
			wantNext:   false,
		},
		{
			name: "forbidden error",
			cfg: config.Headers{
				User:  config.UserHeader{Name: "X-Test-User"},
				Roles: config.RolesHeader{Name: "X-Test-Roles"},
				Token: config.TokenHeader{
					Name:   "X-Test-Token",
					Signer: config.Signer{Secret: "secret"},
				},
			},
			err:        auth.ErrForbidden,
			wantStatus: http.StatusForbidden,
			wantNext:   false,
		},
		{
			name: "unauthorized missing token (challenge expected)",
			cfg: config.Headers{
				User:  config.UserHeader{Name: "X-Test-User"},
				Roles: config.RolesHeader{Name: "X-Test-Roles"},
				Token: config.TokenHeader{Name: "X-Test-Token"},
			},
			err:           token.ErrMissingToken,
			wantStatus:    http.StatusUnauthorized,
			wantNext:      false,
			wantChallenge: true,
		},
		{
			name: "internal error",
			cfg: config.Headers{
				User:  config.UserHeader{Name: "X-Test-User"},
				Roles: config.RolesHeader{Name: "X-Test-Roles"},
				Token: config.TokenHeader{Name: "X-Test-Token"},
			},
			err:        assert.AnError,
			wantStatus: http.StatusInternalServerError,
			wantNext:   false,
		},
		{
			name: "empty user with anonymous allowed (remains anonymous)",
			cfg: config.Headers{
				User:  config.UserHeader{Name: "X-Test-User", Anonymous: true},
				Roles: config.RolesHeader{Name: "X-Test-Roles"},
				Token: config.TokenHeader{
					Name:   "X-Test-Token",
					Signer: config.Signer{Secret: "secret"},
				},
			},
			scope:      rules.Scope{User: ""},
			wantStatus: http.StatusOK,
			wantUser:   "",
			wantRoles:  "",
			wantToken:  "",
			wantNext:   true,
		},
		{
			name: "authenticated no roles -> defaults applied",
			cfg: config.Headers{
				User: config.UserHeader{Name: "X-Test-User"},
				Roles: config.RolesHeader{
					Name:    "X-Test-Roles",
					Default: "r1,r2",
				},
				Token: config.TokenHeader{Name: "X-Test-Token"},
			},
			scope:      rules.Scope{User: "user", Roles: ""},
			wantStatus: http.StatusOK,
			wantUser:   "user",
			wantRoles:  "r1,r2",
			wantToken:  "",
			wantNext:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			guard := mockGuard{scope: tc.scope, err: tc.err}

			var (
				seen  bool
				user  string
				roles string
				token string
			)

			next := http.HandlerFunc(func(
				res http.ResponseWriter,
				req *http.Request,
			) {
				seen = true
				user = req.Header.Get(tc.cfg.User.Name)
				roles = req.Header.Get(tc.cfg.Roles.Name)
				token = req.Header.Get(tc.cfg.Token.Name)
				res.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(
				http.MethodGet,
				"http://example/db/doc",
				nil,
			)

			// Simulate malicious attacker-supplied headers (should be cleared).
			req.Header.Set(tc.cfg.User.Name, "forged")
			req.Header.Set(tc.cfg.Roles.Name, "forged")
			req.Header.Set(tc.cfg.Token.Name, "forged")

			rr := httptest.NewRecorder()
			middleware.Forward(logger.Silent(), guard, tc.cfg)(
				next,
			).ServeHTTP(rr, req)

			assert.Equal(t, tc.wantStatus, rr.Code)
			assert.Equal(
				t,
				tc.wantNext,
				seen,
				"next handler invocation mismatch",
			)

			if tc.wantNext {
				assert.Equal(t, tc.wantUser, user, "user header mismatch")
				assert.Equal(t, tc.wantRoles, roles, "roles header mismatch")

				if tc.wantToken != "" {
					assert.Equal(
						t,
						tc.wantToken,
						token,
						"token digest mismatch",
					)
				} else {
					assert.Empty(t, token, "token header should be empty")
				}
			}

			if tc.wantChallenge {
				got := rr.Header().Get("WWW-Authenticate")
				assert.NotEmpty(t, got, "challenge header expected")
			}
		})
	}
}
