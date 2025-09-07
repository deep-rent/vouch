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

package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/deep-rent/vouch/internal/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyDirectorAndForwardingHeaders(t *testing.T) {
	var got *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(
		res http.ResponseWriter,
		req *http.Request,
	) {
		got = req.Clone(req.Context())
		res.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(res, "ok")
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	h := New(u)

	// Craft the incoming request.
	req := httptest.NewRequest("GET", "http://client.example.local/db/doc", nil)
	req.RemoteAddr = "203.0.113.10:43210"
	req.Header.Set(token.Header, "Bearer abc123")
	req.Header.Set(HeaderForwardedProto, "")
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, got, "upstream not hit")

	assert.Empty(t, got.Header.Get(token.Header))
	assert.Equal(t, "client.example.local", got.Header.Get(HeaderForwardedHost))
	// Forwarded-For may contain a comma‑separated list; just assert our client IP is present.
	ff := got.Header.Get(HeaderForwardedFor)
	assert.NotEmpty(t, ff)
	assert.Contains(t, ff, "203.0.113.10")
	assert.Equal(t, "http", got.Header.Get(HeaderForwardedProto))
}

func TestProxyTimeoutMapsTo504(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(
		res http.ResponseWriter,
		req *http.Request,
	) {
		time.Sleep(200 * time.Millisecond)
		res.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	h := New(u)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	req := httptest.NewRequest("GET", srv.URL+"/slow", nil).WithContext(ctx)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusGatewayTimeout, rr.Code)
}

func TestProxyConnectionErrorMapsTo502(t *testing.T) {
	// Reserve a port then close it so nothing listens there.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	_ = l.Close()

	u, err := url.Parse("http://" + addr)
	require.NoError(t, err)

	h := New(u)

	req := httptest.NewRequest("GET", "http://example.invalid/", nil)
	rr := httptest.NewRecorder()

	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadGateway, rr.Code)
}
