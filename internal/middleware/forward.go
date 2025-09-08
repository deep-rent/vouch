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
	"errors"
	"log/slog"
	"net/http"

	"github.com/deep-rent/vouch/internal/auth"
	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/signer"
	"github.com/deep-rent/vouch/internal/token"
)

// Forward authenticates the request using Guard and, on success, injects proxy
// authentication headers (user, roles, optional HMAC token) for CouchDB.
// It also handles authorization failures and token challenges.
func Forward(log *slog.Logger, grd auth.Guard, cfg config.Headers) Middleware {
	// Optional signer for CouchDB proxy auth token.
	s := signer.New(cfg.Signer)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			// An OPTIONS short-circuit is not needed; the server routes OPTIONS to
			// proxy directly.

			// Authenticate and authorize the request.
			scope, err := grd.Check(req)
			if err != nil {
				var (
					code         int
					unauthorized *token.AuthenticationError
					forbidden    *auth.AuthorizationError
				)
				switch {
				case errors.As(err, &unauthorized):
					res.Header().Set("WWW-Authenticate", unauthorized.Challenge)
					code = http.StatusUnauthorized
				case errors.As(err, &forbidden):
					code = http.StatusForbidden
				default:
					log.Error("auth check failed unexpectedly", "error", err)
					code = http.StatusInternalServerError
				}
				sendStatus(res, code)
				return
			}

			// Never leak client-supplied proxy auth headers.
			req.Header.Del(cfg.User)
			req.Header.Del(cfg.Roles)
			req.Header.Del(cfg.Token)

			if !scope.IsAnonymous() {
				// Authenticated: inject user, roles, and token headers into the request.
				req.Header.Set(cfg.User, scope.User)
				if scope.Roles != "" {
					req.Header.Set(cfg.Roles, scope.Roles)
				}
				if s != nil {
					req.Header.Set(cfg.Token, s.Sign(scope.User))
				}
			} else if !cfg.Anonymous {
				// Anonymous access disabled: require authentication.
				sendStatus(res, http.StatusUnauthorized)
				return
			}

			// Continue down the chain to the proxy.
			next.ServeHTTP(res, req)
		})
	}
}
