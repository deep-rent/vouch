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
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProbePingSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(
		res http.ResponseWriter,
		req *http.Request,
	) {
		assert.Equal(t, "/_up", req.URL.Path)
		res.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	p := newProbe(u)
	require.NoError(t, p.ping(t.Context()))
}

func TestProbePingFailureStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(
		res http.ResponseWriter,
		req *http.Request,
	) {
		res.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	p := newProbe(u)
	err = p.ping(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "health check returned 500")
}

func TestProbePingContextTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(
		res http.ResponseWriter,
		req *http.Request,
	) {
		time.Sleep(150 * time.Millisecond)
		res.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	p := newProbe(u)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	err = p.ping(ctx)
	require.Error(t, err, "expected timeout/cancellation error")
	// Error string differs by platform; just assert not the success path.
}

func TestProbeReadySuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(
		res http.ResponseWriter,
		req *http.Request,
	) {
		res.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	p := newProbe(u)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ready", nil)
	p.ready(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body, _ := io.ReadAll(rr.Body)
	assert.Equal(t, "ready", string(body))
}

func TestProbeReadyNotReady(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(
		res http.ResponseWriter,
		req *http.Request,
	) {
		res.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	p := newProbe(u)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ready", nil)
	p.ready(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
	body, _ := io.ReadAll(rr.Body)
	assert.Equal(t, "not ready\n", string(body)) // http.Error appends newline
}

func TestProbeReadyContextCancelled(t *testing.T) {
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
	p := newProbe(u)

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ready", nil).WithContext(ctx)
	p.ready(rr, req)

	assert.Equal(t, http.StatusServiceUnavailable, rr.Code)
}

func TestProbeHealthy(t *testing.T) {
	// Upstream server is irrelevant for healthy().
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	p := newProbe(u)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/healthy", nil)
	p.healthy(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	body, _ := io.ReadAll(rr.Body)
	assert.Equal(t, "healthy", strings.TrimSpace(string(body)))
}
