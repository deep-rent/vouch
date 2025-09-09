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
	"log/slog"
	"net/http"
	"runtime/debug"
)

// Recover wraps a handler and converts panics into a 500 Internal Server Error.
// It logs the panic value and stack trace along with basic request context.
func Recover(log *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(res http.ResponseWriter, req *http.Request) {
				defer func() {
					// Intercept a panic from downstream handlers/middlewares.
					if err := recover(); err != nil {
						method, path := req.Method, req.URL.Path
						log.Error("unhandled panic",
							"method", method,
							"path", path,
							"panic", err,
							"stack", string(debug.Stack()),
						)
						sendStatus(res, http.StatusInternalServerError)
					}
				}()
				next.ServeHTTP(res, req)
			},
		)
	}
}
