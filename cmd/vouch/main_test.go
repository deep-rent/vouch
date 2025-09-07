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
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

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

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	return path
}

func TestRunConfigLoadError(t *testing.T) {
	f := &flags{path: "does-not-exist.yaml"}
	err := run(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "couldn't load config")
}

func TestRunInterruptGraceful(t *testing.T) {
	// Use dynamic port (127.0.0.1:0) to let server start.
	cfg := `
proxy:
  listen: 127.0.0.1:0
token:
  keys:
    remote:
      endpoint: https://example.com/jwks
rules:
  - mode: allow
    when: "true"
`
	f := &flags{path: writeConfig(t, cfg)}
	done := make(chan error, 1)
	go func() {
		done <- run(f)
	}()

	// Give the server a moment to start, then send SIGTERM.
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGTERM))

	select {
	case err := <-done:
		require.NoError(t, err, "graceful shutdown should not return error")
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return after signal")
	}
}

func TestMainVersionFlag(t *testing.T) {
	if os.Getenv("TEST_MAIN_VERSION") == "1" {
		// Child process path: run main() with -v to trigger version output & exit(0).
		os.Args = []string{"vouch", "-v"}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run", "TestMainVersionFlag")
	cmd.Env = append(os.Environ(), "TEST_MAIN_VERSION=1")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	require.NoError(t, err, "expected main to exit with code 0 for -v flag")

	assert.Contains(t, out.String(), "version:", "expected version line in output")
}
