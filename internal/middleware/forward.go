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
	"github.com/deep-rent/vouch/internal/hash"
	"github.com/deep-rent/vouch/internal/token"
)

func Forward(log *slog.Logger, grd *auth.Guard, cfg config.Headers) Middleware {
	var sign *hash.Signer
	if secret := cfg.Secret; secret != "" {
		sign = hash.New(secret)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			// An OPTIONS short-circuit is not needed; the server routes OPTIONS to
			// proxy directly.

			scope, err := grd.Check(req)
			if err == auth.ErrForbidden {
				code := http.StatusForbidden
				http.Error(res, http.StatusText(code), code)
				return
			}
			var unauthorized *token.AuthenticationError
			if errors.As(err, &unauthorized) {
				res.Header().Set("WWW-Authenticate", unauthorized.Challenge)
				code := http.StatusUnauthorized
				http.Error(res, http.StatusText(code), code)
				return
			}
			if err != nil {
				log.Error("auth check failed", "error", err)
				code := http.StatusInternalServerError
				http.Error(res, http.StatusText(code), code)
				return
			}

			// Never leak client-supplied proxy auth headers
			req.Header.Del(cfg.User)
			req.Header.Del(cfg.Roles)
			req.Header.Del(cfg.Token)

			if user := scope.User; user != "" {
				res.Header().Set(cfg.User, user)

				if role := scope.Role; role != "" {
					res.Header().Set(cfg.Roles, role)
				}
				if sign != nil {
					res.Header().Set(cfg.Token, sign.Sign(user))
				}
			} else if !cfg.Anonymous {
				code := http.StatusUnauthorized
				http.Error(res, http.StatusText(code), code)
			}

			next.ServeHTTP(res, req)
		})
	}
}
