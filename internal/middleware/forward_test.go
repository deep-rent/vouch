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

type testGuard struct {
	scope auth.Scope
	err   error
}

func (g testGuard) Check(*http.Request) (auth.Scope, error) {
	return g.scope, g.err
}

func TestForwardSuccessAuthenticated(t *testing.T) {
	cfg := config.Headers{
		User:   "X-Auth-CouchDB-UserName",
		Roles:  "X-Auth-CouchDB-Roles",
		Token:  "X-Auth-CouchDB-Token",
		Secret: "secret",
		// Anonymous default (false) is fine; user is set anyway.
	}

	guard := testGuard{
		scope: auth.Scope{User: "user", Roles: "r1,r2"},
	}

	var sawHandler bool
	var receivedUser, receivedRoles, receivedToken string

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHandler = true
		receivedUser = r.Header.Get(cfg.User)
		receivedRoles = r.Header.Get(cfg.Roles)
		receivedToken = r.Header.Get(cfg.Token)
		w.WriteHeader(http.StatusOK)
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)

	req := httptest.NewRequest("GET", "http://example/db/doc", nil)
	// Simulate malicious client‑supplied headers (must be stripped).
	req.Header.Set(cfg.User, "attacker")
	req.Header.Set(cfg.Roles, "evil")
	req.Header.Set(cfg.Token, "forged")

	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	require.True(t, sawHandler, "next handler not invoked")
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "user", receivedUser)
	assert.Equal(t, "r1,r2", receivedRoles)
	// Deterministic HMAC (aligned with signer_test expectations).
	assert.Equal(t, "027da48c8c642ca4c58eb982eec81915179e77a3", receivedToken)
}

func TestForwardSuccessAuthenticatedNoRolesNoSecret(t *testing.T) {
	cfg := config.Headers{
		User:      "X-Auth-CouchDB-UserName",
		Roles:     "X-Auth-CouchDB-Roles",
		Token:     "X-Auth-CouchDB-Token",
		Secret:    "", // disables signing
		Anonymous: true,
	}

	guard := testGuard{
		scope: auth.Scope{User: "user"}, // no roles
	}

	var sawHandler bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHandler = true
		assert.Equal(t, "user", r.Header.Get(cfg.User))
		assert.Empty(t, r.Header.Get(cfg.Roles))
		assert.Empty(t, r.Header.Get(cfg.Token)) // no secret => no token header
		w.WriteHeader(http.StatusOK)
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	require.True(t, sawHandler)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestForwardSuccessAnonymousAllowed(t *testing.T) {
	cfg := config.Headers{
		User:      "X-Auth-CouchDB-UserName",
		Roles:     "X-Auth-CouchDB-Roles",
		Token:     "X-Auth-CouchDB-Token",
		Secret:    "secret",
		Anonymous: true, // allow anonymous
	}

	guard := testGuard{
		scope: auth.Scope{}, // anonymous
	}

	var sawHandler bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHandler = true
		assert.Empty(t, r.Header.Get(cfg.User))
		assert.Empty(t, r.Header.Get(cfg.Roles))
		assert.Empty(t, r.Header.Get(cfg.Token))
		w.WriteHeader(http.StatusOK)
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	require.True(t, sawHandler)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestForwardAnonymousRejected(t *testing.T) {
	cfg := config.Headers{
		User:      "X-Auth-CouchDB-UserName",
		Roles:     "X-Auth-CouchDB-Roles",
		Token:     "X-Auth-CouchDB-Token",
		Anonymous: false,
	}

	guard := testGuard{
		scope: auth.Scope{},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called for rejected anonymous request")
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestForwardForbidden(t *testing.T) {
	cfg := config.Headers{
		User:  "X-Auth-CouchDB-UserName",
		Roles: "X-Auth-CouchDB-Roles",
		Token: "X-Auth-CouchDB-Token",
	}

	guard := testGuard{
		err: auth.ErrForbidden,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called for forbidden request")
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestForwardUnauthorizedChallenge(t *testing.T) {
	cfg := config.Headers{
		User:  "X-Auth-CouchDB-UserName",
		Roles: "X-Auth-CouchDB-Roles",
		Token: "X-Auth-CouchDB-Token",
	}

	guard := testGuard{
		err: token.ErrMissingToken,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called for unauthorized request")
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.NotEmpty(t, rr.Header().Get("WWW-Authenticate"))
}

func TestForwardInternalError(t *testing.T) {
	cfg := config.Headers{
		User:  "X-Auth-CouchDB-UserName",
		Roles: "X-Auth-CouchDB-Roles",
		Token: "X-Auth-CouchDB-Token",
	}

	guard := testGuard{
		err: assert.AnError,
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("handler should not be called on internal error")
	})

	mw := Forward(logger.Silent(), guard, cfg)(next)

	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}
