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
	"github.com/stretchr/testify/require"
)

type mockGuard struct {
	scope auth.Scope
	err   error
}

func (g mockGuard) Check(*http.Request) (auth.Scope, error) {
	return g.scope, g.err
}

func TestForwardSuccessAuthenticated(t *testing.T) {
	cfg := config.Headers{
		User:   "X-Test-User",
		Roles:  "X-Test-Roles",
		Token:  "X-Test-Token",
		Secret: "secret",
	}

	guard := mockGuard{
		scope: auth.Scope{
			User:  "test",
			Roles: "foo,bar",
		},
	}

	var seen bool
	var user, roles, token string

	next := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		seen = true
		user = req.Header.Get(cfg.User)
		roles = req.Header.Get(cfg.Roles)
		token = req.Header.Get(cfg.Token)
		res.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "http://example/db/doc", nil)
	// Simulate malicious client‑supplied headers (must be stripped).
	req.Header.Set(cfg.User, "attacker")
	req.Header.Set(cfg.Roles, "evil")
	req.Header.Set(cfg.Token, "forged")

	mw := Forward(logger.Silent(), guard, cfg)(next)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	require.True(t, seen, "next handler not invoked")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "test", user)
	assert.Equal(t, "foo,bar", roles)
	assert.Equal(t, "0329a06b62cd16b33eb6792be8c60b158d89a2ee3a876fce9a881ebb488c0914", token)
}

func TestForwardSuccessAuthenticatedNoRolesNoSecret(t *testing.T) {
	cfg := config.Headers{
		User:      "X-Test-User",
		Roles:     "X-Test-Roles",
		Token:     "X-Test-Token",
		Secret:    "",
		Anonymous: true,
	}

	guard := mockGuard{
		scope: auth.Scope{User: "user"},
	}

	var seen bool
	next := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		seen = true
		assert.Equal(t, "user", req.Header.Get(cfg.User))
		assert.Empty(t, req.Header.Get(cfg.Roles))
		assert.Empty(t, req.Header.Get(cfg.Token))
		res.WriteHeader(http.StatusOK)
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	require.True(t, seen)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestForwardSuccessAnonymousAllowed(t *testing.T) {
	cfg := config.Headers{
		User:      "X-Test-User",
		Roles:     "X-Test-Roles",
		Token:     "X-Test-Token",
		Secret:    "secret",
		Anonymous: true,
	}

	guard := mockGuard{
		scope: auth.Scope{},
	}

	var seen bool
	next := http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		seen = true
		assert.Empty(t, req.Header.Get(cfg.User))
		assert.Empty(t, req.Header.Get(cfg.Roles))
		assert.Empty(t, req.Header.Get(cfg.Token))
		res.WriteHeader(http.StatusOK)
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	require.True(t, seen)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestForwardAnonymousRejected(t *testing.T) {
	cfg := config.Headers{
		User:      "X-Test-User",
		Roles:     "X-Test-Roles",
		Token:     "X-Test-Token",
		Anonymous: false,
	}

	guard := mockGuard{
		scope: auth.Scope{},
	}

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("handler should not be called for rejected anonymous request")
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestForwardForbidden(t *testing.T) {
	cfg := config.Headers{
		User:  "X-Test-User",
		Roles: "X-Test-Roles",
		Token: "X-Test-Token",
	}

	guard := mockGuard{
		err: auth.ErrForbidden,
	}

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("handler should not be called for forbidden request")
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestForwardUnauthorizedChallenge(t *testing.T) {
	cfg := config.Headers{
		User:  "X-Test-User",
		Roles: "X-Test-Roles",
		Token: "X-Test-Token",
	}

	guard := mockGuard{
		err: token.ErrMissingToken,
	}

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("handler should not be called for unauthorized request")
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("WWW-Authenticate"))
}

func TestForwardInternalError(t *testing.T) {
	cfg := config.Headers{
		User:  "X-Test-User",
		Roles: "X-Test-Roles",
		Token: "X-Test-Token",
	}

	guard := mockGuard{
		err: assert.AnError,
	}

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatalf("handler should not be called on internal error")
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
