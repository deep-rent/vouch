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

func TestChainOrder(t *testing.T) {
	var calls []string

	m1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			calls = append(calls, "m1")
			next.ServeHTTP(res, req)
		})
	}
	m2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			calls = append(calls, "m2")
			next.ServeHTTP(res, req)
		})
	}
	m3 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			calls = append(calls, "m3")
			next.ServeHTTP(res, req)
		})
	}

	h0 := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls = append(calls, "h0")
	})

	chained := Chain(h0, m1, m2, m3)

	req := httptest.NewRequest("GET", "/", nil)
	chained.ServeHTTP(httptest.NewRecorder(), req)

	require.Equal(t, []string{"m1", "m2", "m3", "h0"}, calls)
}
