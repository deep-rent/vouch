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

package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerRoutesAndMiddleware(t *testing.T) {
	var mu sync.Mutex
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
		mu.Lock()
		calls = append(calls, req.Method+" "+req.URL.Path)
		mu.Unlock()
		res.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(res, "ok")
	}))
	defer srv.Close()

	var mw []string
	m1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			mw = append(mw, "m1")
			next.ServeHTTP(res, req)
		})
	}
	m2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
			mw = append(mw, "m2")
			next.ServeHTTP(res, req)
		})
	}

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	s := New(u, m1, m2)

	api := httptest.NewServer(s.mux)
	defer api.Close()

	res, err := http.Get(api.URL + "/healthy")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	body, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	assert.Equal(t, "healthy", string(body))
	mu.Lock()
	assert.Empty(t, calls)
	mu.Unlock()

	res, err = http.Get(api.URL + "/ready")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	mu.Lock()
	require.Contains(t, calls, "GET /_up")
	mu.Unlock()

	res, err = http.Get(api.URL + "/db/doc")
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	mu.Lock()
	require.Contains(t, calls, "GET /db/doc")
	mu.Unlock()
	assert.Equal(t, []string{"m1", "m2"}, mw)

	mw = nil
	req, _ := http.NewRequest(http.MethodOptions, api.URL+"/any/path", nil)
	res, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.StatusCode)
	assert.Empty(t, mw)
	mu.Lock()
	require.Contains(t, calls, "OPTIONS /any/path")
	mu.Unlock()
}

func TestServerReadyFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(
		res http.ResponseWriter,
		req *http.Request,
	) {
		if req.URL.Path == "/_up" {
			res.WriteHeader(http.StatusInternalServerError)
			return
		}
		res.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	s := New(u)
	api := httptest.NewServer(s.mux)
	defer api.Close()

	res, err := http.Get(api.URL + "/ready")
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, res.StatusCode)
	_ = res.Body.Close()
}

func TestShutdownWithoutStartIsNoop(t *testing.T) {
	s := &Server{}
	err := s.Shutdown(t.Context())
	require.NoError(t, err)
}
