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

	"github.com/stretchr/testify/require"
)

func trace(label string, calls *[]string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			*calls = append(*calls, label)
			next.ServeHTTP(res, req)
		})
	}
}

func TestChain(t *testing.T) {
	tests := []struct {
		name  string
		mws   []Middleware
		order []string
	}{
		{
			name:  "three middlewares",
			mws:   nil, // filled in below to reuse trace helper
			order: []string{"m1", "m2", "m3", "h0"},
		},
		{
			name:  "single middleware",
			order: []string{"m1", "h0"},
		},
		{
			name:  "no middleware",
			order: []string{"h0"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			var calls []string

			// Build middleware list based on desired order length minus final handler.
			switch len(tt.order) {
			case 4: // m1 m2 m3 h0
				tt.mws = []Middleware{
					trace("m1", &calls),
					trace("m2", &calls),
					trace("m3", &calls),
				}
			case 2: // m1 h0
				tt.mws = []Middleware{
					trace("m1", &calls),
				}
			case 1:
				tt.mws = nil
			}

			h0 := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				calls = append(calls, "h0")
			})

			chained := Chain(h0, tt.mws...)
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			chained.ServeHTTP(httptest.NewRecorder(), req)

			require.Equal(t, tt.order, calls)
		})
	}
}
