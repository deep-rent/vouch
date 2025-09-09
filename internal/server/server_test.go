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

package server_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/deep-rent/vouch/internal/config"
	"github.com/deep-rent/vouch/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServerRoutesAndMiddleware(t *testing.T) {
	var mu sync.Mutex
	var calls []string

	srv := httptest.NewServer(http.HandlerFunc(func(
		res http.ResponseWriter,
		req *http.Request,
	) {
		mu.Lock()
		calls = append(calls, req.Method+" "+req.URL.Path)
		mu.Unlock()
		res.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(res, "ok")
	}))
	defer srv.Close()

	var mw []string
	m1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(res http.ResponseWriter, req *http.Request) {
				mw = append(mw, "m1")
				next.ServeHTTP(res, req)
			},
		)
	}
	m2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(res http.ResponseWriter, req *http.Request) {
				mw = append(mw, "m2")
				next.ServeHTTP(res, req)
			},
		)
	}

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	cfg := config.Server{
		Local: config.Local{
			Addr: "127.0.0.1:0",
		},
		Proxy: config.Proxy{
			Target: u,
		},
	}
	s := server.New(cfg, m1, m2)

	api := httptest.NewServer(s.Handler())
	defer api.Close()

	reset := func() {
		mu.Lock()
		calls = nil
		mu.Unlock()
		mw = nil
	}

	t.Run("proxy GET applies middleware and forwards", func(t *testing.T) {
		reset()
		res, err := http.Get(api.URL + "/db/doc")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		mu.Lock()
		require.Contains(t, calls, "GET /db/doc")
		mu.Unlock()
		assert.Equal(t, []string{"m1", "m2"}, mw, "middleware order mismatch")
	})

	t.Run("OPTIONS bypasses middleware but is forwarded", func(t *testing.T) {
		reset()
		req, _ := http.NewRequest(http.MethodOptions, api.URL+"/any/path", nil)
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)

		assert.Empty(t, mw, "middleware should not run for OPTIONS")
		mu.Lock()
		require.Contains(t, calls, "OPTIONS /any/path")
		mu.Unlock()
	})

	t.Run("GET /_up bypasses middleware", func(t *testing.T) {
		res, err := http.Get(api.URL + "/_up")
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		_ = res.Body.Close()
		assert.Empty(t, mw, "middleware must not run for GET /_up")
		mu.Lock()
		assert.Contains(t, calls, "GET /_up")
		mu.Unlock()
	})

	t.Run("HEAD /_up bypasses middleware", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodHead, api.URL+"/_up", nil)
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, res.StatusCode)
		_ = res.Body.Close()
		assert.Empty(t, mw, "middleware must not run for HEAD /_up")
		mu.Lock()
		assert.Contains(t, calls, "HEAD /_up")
		mu.Unlock()
	})
}

func TestShutdownWithoutStartIsNoop(t *testing.T) {
	s := server.New(config.Server{})
	err := s.Shutdown(t.Context())
	require.NoError(t, err)
}

func TestServerStartAndShutdown(t *testing.T) {
	// Upstream fake CouchDB.
	srv := httptest.NewServer(http.HandlerFunc(func(
		res http.ResponseWriter,
		req *http.Request,
	) {
		if req.URL.Path == "/_up" {
			res.WriteHeader(http.StatusOK)
			return
		}
		res.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	// Pick a free port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())

	cfg := config.Server{
		Local: config.Local{
			Addr: addr,
		},
		Proxy: config.Proxy{
			Target: u,
		},
	}
	s := server.New(cfg)

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start()
	}()

	// Wait until server responds (with timeout) by probing /_up passthrough.
	deadline := time.Now().Add(2 * time.Second)
	var ready bool
	for time.Now().Before(deadline) {
		res, err := http.Get(fmt.Sprintf("http://%s/_up", addr))
		if err == nil {
			_ = res.Body.Close()
			if res.StatusCode == http.StatusOK {
				ready = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	require.True(t, ready, "server never became ready")

	// Graceful shutdown.
	wait, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	require.NoError(t, s.Shutdown(wait))

	// Start must return nil on graceful shutdown.
	require.NoError(t, <-errCh)
}

func TestServerStartPortInUse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(
		res http.ResponseWriter, _ *http.Request,
	) {
		res.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	l, err := net.Listen("tcp", "127.0.0.1:0") // Occupy a port.
	require.NoError(t, err)
	addr := l.Addr().String()
	defer l.Close()

	cfg := config.Server{
		Local: config.Local{
			Addr: addr,
		},
		Proxy: config.Proxy{
			Target: u,
		},
	}

	s := server.New(cfg)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Start()
	}()

	// Expect an error (address already in use) shortly.
	select {
	case e := <-errCh:
		require.Error(t, e)
	default:
		// Allow a little time if not immediate.
		select {
		case e := <-errCh:
			require.Error(t, e)
		case <-time.After(500 * time.Millisecond):
			t.Fatal("expected Start to fail due to port already in use")
		}
	}
}
