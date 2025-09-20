package logger

import (
	"log/slog"
	"os"
	"strings"
)

// New creates a new structured logger instance that logs at the specified
// level. Supported levels are "debug", "info", "warn", and "error". If an
// unsupported level is provided, it falls back to "info". The level is
// case-insensitive and ignores leading or trailing whitespace.
func New(at string) *slog.Logger {
	level := slog.LevelInfo // Default level
	switch strings.ToUpper(strings.TrimSpace(at)) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	}
	return slog.New(slog.NewJSONHandler(
		os.Stdout,
		&slog.HandlerOptions{
			Level: level,
		}),
	)
}
