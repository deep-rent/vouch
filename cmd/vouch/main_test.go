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

package main

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	args := os.Args
	defer func() { os.Args = args }()

	tests := []struct {
		name string
		args []string
		env  string
		want flags
	}{
		{
			name: "default path",
			args: []string{"vouch"},
			env:  "",
			want: flags{path: "./config.yaml"},
		},
		{
			name: "environment variable overrides default",
			args: []string{"vouch"},
			env:  "env.yaml",
			want: flags{path: "env.yaml"},
		},
		{
			name: "short flag overrides environment variable",
			args: []string{"vouch", "-c", "arg.yaml"},
			env:  "env.yaml",
			want: flags{path: "arg.yaml"},
		},
		{
			name: "long flag overrides environment variable",
			args: []string{"vouch", "--config", "arg.yaml"},
			env:  "env.yaml",
			want: flags{path: "arg.yaml"},
		},
		{
			name: "long flag with equals overrides environment variable",
			args: []string{"vouch", "--config=arg.yaml"},
			env:  "env.yaml",
			want: flags{path: "arg.yaml"},
		},
		{
			name: "short version flag",
			args: []string{"vouch", "-v"},
			env:  "",
			want: flags{path: "./config.yaml", version: true},
		},
		{
			name: "long version flag",
			args: []string{"vouch", "--version"},
			env:  "",
			want: flags{path: "./config.yaml", version: true},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.args
			if tc.env != "" {
				t.Setenv("VOUCH_CONFIG", tc.env)
			} else {
				os.Unsetenv("VOUCH_CONFIG")
			}

			f, err := parse()
			require.NoError(t, err)
			assert.Equal(t, tc.want.path, f.path, "unexpected config path")
			assert.Equal(t, tc.want.version, f.version, "unexpected version flag")
		})
	}
}

func TestLogger(t *testing.T) {
	tests := []struct {
		name string
		env  string
		want slog.Level
	}{
		{"debug", "DEBUG", slog.LevelDebug},
		{"info", "INFO", slog.LevelInfo},
		{"warn", "WARN", slog.LevelWarn},
		{"error", "ERROR", slog.LevelError},
		{"lowercase", "debug", slog.LevelDebug},
		{"empty", "", slog.LevelInfo},
		{"invalid", "invalid", slog.LevelInfo},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VOUCH_LOG", tc.env)
			log := logger()

			handler, ok := log.Handler().(*slog.JSONHandler)
			require.True(t, ok, "expected *slog.JSONHandler, got %T", log.Handler())

			assert.True(t, handler.Enabled(t.Context(), tc.want),
				"expected level %v to be enabled", tc.want)

			if tc.want > slog.LevelDebug {
				assert.False(t, handler.Enabled(t.Context(), tc.want-1),
					"expected lower level than %v to be disabled", tc.want)
			}
		})
	}
}
