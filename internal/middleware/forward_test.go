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

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/logger"
	"github.com/deep-rent/vouch/internal/token"
	"github.com/stretchr/testify/assert"
)

type mockGuard struct {
	scope auth.Scope
	err   error
}

func (g mockGuard) Check(*http.Request) (auth.Scope, error) {
	return g.scope, g.err
}

func TestForward(t *testing.T) {
	tests := []struct {
		// inputs
		name  string
		cfg   config.Headers
		scope auth.Scope
		err   error
		// expected outputs
		status    int
		user      string
		roles     string
		token     string
		next      bool
		challenge bool
	}{
		{
			name: "authenticated with roles + secret (signed token)",
			cfg: config.Headers{
				User:  "X-Test-User",
				Roles: "X-Test-Roles",
				Token: "X-Test-Token",
				Signer: config.Signer{
					Secret: "secret",
				},
			},
			scope: auth.Scope{User: "test", Roles: "foo,bar"},
			// Digest observed in existing dedicated test; keep deterministic assertion.
			token:  "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914",
			status: http.StatusOK,
			user:   "test",
			roles:  "foo,bar",
			next:   true,
		},
		{
			name: "authenticated no roles no secret",
			cfg: config.Headers{
				User:      "X-Test-User",
				Roles:     "X-Test-Roles",
				Token:     "X-Test-Token",
				Signer:    config.Signer{},
				Anonymous: true,
			},
			scope:  auth.Scope{User: "user"},
			status: http.StatusOK,
			user:   "user",
			roles:  "",
			token:  "",
			next:   true,
		},
		{
			name: "anonymous allowed (secret present) => no auth headers injected",
			cfg: config.Headers{
				User:  "X-Test-User",
				Roles: "X-Test-Roles",
				Token: "X-Test-Token",
				Signer: config.Signer{
					Secret: "secret",
				},
				Anonymous: true,
			},
			scope:  auth.Scope{},
			status: http.StatusOK,
			user:   "",
			roles:  "",
			token:  "",
			next:   true,
		},
		{
			name: "anonymous rejected (not allowed)",
			cfg: config.Headers{
				User:      "X-Test-User",
				Roles:     "X-Test-Roles",
				Token:     "X-Test-Token",
				Anonymous: false,
			},
			scope:  auth.Scope{},
			status: http.StatusUnauthorized,
			next:   false,
		},
		{
			name: "forbidden error",
			cfg: config.Headers{
				User:  "X-Test-User",
				Roles: "X-Test-Roles",
				Token: "X-Test-Token",
			},
			err:    auth.ErrForbidden,
			status: http.StatusForbidden,
			next:   false,
		},
		{
			name: "unauthorized missing token (challenge expected)",
			cfg: config.Headers{
				User:  "X-Test-User",
				Roles: "X-Test-Roles",
				Token: "X-Test-Token",
			},
			err:       token.ErrMissingToken,
			status:    http.StatusUnauthorized,
			next:      false,
			challenge: true,
		},
		{
			name: "internal error",
			cfg: config.Headers{
				User:  "X-Test-User",
				Roles: "X-Test-Roles",
				Token: "X-Test-Token",
			},
			err:    assert.AnError,
			status: http.StatusInternalServerError,
			next:   false,
		},
		{
			name: "empty user with anonymous allowed (remains anonymous)",
			cfg: config.Headers{
				User:  "X-Test-User",
				Roles: "X-Test-Roles",
				Token: "X-Test-Token",
				Signer: config.Signer{
					Secret: "secret",
				},
				Anonymous: true,
			},
			scope:  auth.Scope{User: ""},
			status: http.StatusOK,
			user:   "",
			roles:  "",
			token:  "",
			next:   true,
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
				user = req.Header.Get(tc.cfg.User)
				roles = req.Header.Get(tc.cfg.Roles)
				token = req.Header.Get(tc.cfg.Token)
				res.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "http://example/db/doc", nil)

			// Simulate malicious attacker-supplied headers (should be cleared).
			req.Header.Set(tc.cfg.User, "forged")
			req.Header.Set(tc.cfg.Roles, "forged")
			req.Header.Set(tc.cfg.Token, "forged")

			rr := httptest.NewRecorder()
			Forward(logger.Silent(), guard, tc.cfg)(next).ServeHTTP(rr, req)

			assert.Equal(t, tc.status, rr.Code)
			assert.Equal(t, tc.next, seen, "next handler invocation mismatch")

			if tc.next {
				assert.Equal(t, tc.user, user, "user header mismatch")
				assert.Equal(t, tc.roles, roles, "roles header mismatch")

				if tc.token != "" {
					assert.Equal(t, tc.token, token, "token digest mismatch")
				} else {
					assert.Empty(t, token, "token header should be empty")
				}
			}

			if tc.challenge {
				got := rr.Header().Get("WWW-Authenticate")
				assert.NotEmpty(t, got, "challenge header expected")
			}
		})
	}
}
