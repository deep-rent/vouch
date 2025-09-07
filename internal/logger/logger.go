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
	"io"
	"log/slog"
	"os"
	"strings"
)

// New returns a structured JSON logger configured at the requested
// level. The argument is case-insensitive and trimmed. Supported values:
//
//	debug  -> slog.LevelDebug
//	info   -> slog.LevelInfo (default for empty/unknown)
//	warn   -> slog.LevelWarn
//	error  -> slog.LevelError
//	silent -> returns the result of Silent() (no output)
//
// Any unknown or empty value falls back to INFO. Passing "silent"
// returns a discard logger, allowing callers to suppress output
// without branching.
func New(v string) *slog.Logger {
	var level slog.Level
	switch strings.ToUpper(strings.TrimSpace(v)) {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	case "SILENT":
		return Silent()
	default:
		level = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{
			Level: level,
		},
	))
}

// Silent returns a slog.Logger whose handler discards all output.
// Useful for tests or environments where logging must be disabled.
func Silent() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
