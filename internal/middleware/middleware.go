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

import "net/http"

// Middleware wraps a HTTP handler to form a middleware chain for adding
// cross-cutting behavior.
type Middleware func(http.Handler) http.Handler

// Chain composes middleware handlers (outermost first).
// Middlewares are applied in the order provided.
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	// Apply in reverse so the first middleware wraps last.
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// sendStatus sends an HTTP response with the given status code and
// corresponding status text as the body.
func sendStatus(res http.ResponseWriter, code int) {
	http.Error(res, http.StatusText(code), code)
}
