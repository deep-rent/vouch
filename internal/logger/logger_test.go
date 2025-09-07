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

package logger

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLevelMapping(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected slog.Level
		handler  any
	}{
		{name: "debug", input: "DEBUG", expected: slog.LevelDebug, handler: &slog.JSONHandler{}},
		{name: "sanitization", input: "  debug  ", expected: slog.LevelDebug, handler: &slog.JSONHandler{}},
		{name: "info", input: "INFO", expected: slog.LevelInfo, handler: &slog.JSONHandler{}},
		{name: "warn", input: "WARN", expected: slog.LevelWarn, handler: &slog.JSONHandler{}},
		{name: "error", input: "ERROR", expected: slog.LevelError, handler: &slog.JSONHandler{}},
		{name: "silent", input: "SILENT", handler: &slog.TextHandler{}},
		{name: "empty", input: "", expected: slog.LevelInfo, handler: &slog.JSONHandler{}},
		{name: "unknown", input: "UNKNOWN", expected: slog.LevelInfo, handler: &slog.JSONHandler{}},
	}

	ctx := context.Background()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log := New(tc.input)
			require.NotNil(t, log)

			// Handler type expectation
			require.IsType(t, tc.handler, log.Handler())

			// Skip level checks for SILENT (it returns a different handler that discards output;
			// its Enabled behavior is not tied to a sentinel level in this implementation).
			if tc.input == "SILENT" {
				// Still should not panic when logging.
				log.Debug("debug")
				return
			}

			// Expected level should be enabled.
			assert.True(t, log.Handler().Enabled(ctx, tc.expected), "expected level %v enabled", tc.expected)

			// One step lower than expected should be disabled (except when expected is Debug).
			if tc.expected != slog.LevelDebug {
				lower := tc.expected - 4 // slog levels use increments of 4
				assert.False(t, log.Handler().Enabled(ctx, lower), "expected level %v disabled", lower)
			}

			// One step higher should be enabled.
			higher := tc.expected + 4
			assert.True(t, log.Handler().Enabled(ctx, higher), "expected higher level %v enabled", higher)
		})
	}
}

func TestSilentHelper(t *testing.T) {
	log := Silent()
	require.NotNil(t, log)

	log.Debug("debug")
	log.Info("info")
	log.Warn("warn")
	log.Error("error")
}

func TestNewReturnsDistinctInstances(t *testing.T) {
	a := New("info")
	b := New("info")
	require.NotSame(t, a, b)
}
