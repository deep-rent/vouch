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

package logger_test

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLevelMapping(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		level   slog.Level
		handler any
	}{
		{name: "debug", input: "DEBUG", level: slog.LevelDebug, handler: &slog.JSONHandler{}},
		{name: "sanitization", input: "  debug  ", level: slog.LevelDebug, handler: &slog.JSONHandler{}},
		{name: "info", input: "INFO", level: slog.LevelInfo, handler: &slog.JSONHandler{}},
		{name: "warn", input: "WARN", level: slog.LevelWarn, handler: &slog.JSONHandler{}},
		{name: "error", input: "ERROR", level: slog.LevelError, handler: &slog.JSONHandler{}},
		{name: "silent", input: "SILENT", handler: &slog.TextHandler{}},
		{name: "empty", input: "", level: slog.LevelInfo, handler: &slog.JSONHandler{}},
		{name: "unknown", input: "UNKNOWN", level: slog.LevelInfo, handler: &slog.JSONHandler{}},
	}

	ctx := t.Context()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			log := New(tc.input)

			require.NotNil(t, log)
			require.IsType(t, tc.handler, log.Handler())

			// Skip level checks for SILENT (it returns a different handler that discards output;
			// its Enabled behavior is not tied to a sentinel level in this implementation).
			if tc.input == "SILENT" {
				// Just ensure that logging at any level does not panic.
				log.Debug("debug")
				return
			}

			// (1) Expected level should be enabled.
			{
				on := log.Handler().Enabled(ctx, tc.level)
				assert.True(t, on, "expected level %v enabled", tc.level)
			}
			// (2) One step lower than expected should be disabled (except when on debug).
			if tc.level != slog.LevelDebug {
				prev := tc.level - 4 // slog levels use increments of 4
				on := log.Handler().Enabled(ctx, prev)
				assert.False(t, on, "expected lower level %v disabled", prev)
			}
			// (3) One step higher should be enabled.
			{
				next := tc.level + 4
				on := log.Handler().Enabled(ctx, next)
				assert.True(t, on, "expected higher level %v enabled", next)
			}
		})
	}
}

func TestNewReturnsDistinctInstances(t *testing.T) {
	a := New("info")
	b := New("info")
	require.NotSame(t, a, b)
}

func TestSilent(t *testing.T) {
	log := Silent()
	require.NotNil(t, log)

	log.Debug("debug")
	log.Info("info")
	log.Warn("warn")
	log.Error("error")
}
