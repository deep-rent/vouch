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
	"context"
	"log/slog"
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	args := os.Args // Hold and restore original arguments.
	defer func() { os.Args = args }()

	tests := []struct {
		name string
		args []string
		env  string
		want string
	}{
		{
			name: "default path",
			args: []string{"vouch"},
			env:  "",
			want: "./config.yaml",
		},
		{
			name: "env var overrides default",
			args: []string{"vouch"},
			env:  "env.yaml",
			want: "env.yaml",
		},
		{
			name: "flag overrides env var",
			args: []string{"vouch", "-c", "arg.yaml"},
			env:  "env.yaml",
			want: "arg.yaml",
		},
		{
			name: "flag without env var",
			args: []string{"vouch", "-c", "arg.yaml"},
			env:  "",
			want: "arg.yaml",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.args
			if tc.env != "" {
				t.Setenv("VOUCH_CONFIG", tc.env)
			} else {
				// Unset to avoid interference from previous tests.
				os.Unsetenv("VOUCH_CONFIG")
			}

			f, err := parse()
			if err != nil {
				t.Fatalf("parse() error = %v", err)
			}
			if f.path != tc.want {
				t.Errorf("parse() path = %q, want %q", f.path, tc.want)
			}
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
			// Check if the handler has the correct level enabled.
			if !log.Handler().Enabled(context.Background(), tc.want) {
				t.Errorf("logger level %v should be enabled", tc.want)
			}
			// Check that a level below the desired one is disabled.
			if tc.want > slog.LevelDebug && log.Handler().Enabled(context.Background(), tc.want-1) {
				t.Errorf("logger level below %v should be disabled", tc.want)
			}
		})
	}
}
