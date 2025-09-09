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
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func newLogger() (*bytes.Buffer, *slog.Logger) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))
	return &buf, log
}

func TestRecoverPanic(t *testing.T) {
	buf, log := newLogger()
	h := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom!")
	})

	mw := Recover(log)(h)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, httptest.NewRequest("GET", "/panic", nil))

	require.Equal(t, http.StatusInternalServerError, rr.Code)
	out := buf.String()
	require.Contains(t, out, "unhandled panic")
	require.Contains(t, out, "boom!")
	require.Contains(t, out, "stack")
}

func TestRecoverWithoutPanic(t *testing.T) {
	buf, log := newLogger()
	h := http.HandlerFunc(func(res http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(res, "ok")
	})

	rr := httptest.NewRecorder()
	Recover(log)(h).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	require.Equal(t, http.StatusOK, rr.Code)
	require.Equal(t, "ok", rr.Body.String())
	require.Empty(t, buf.String(), "no log output expected without panic")
}
