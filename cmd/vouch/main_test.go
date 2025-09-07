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
	"fmt"
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

func TestRunConfigLoadError(t *testing.T) {
	f := &flags{path: "does-not-exist.yaml"}
	err := run(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "couldn't load config")
}

func TestRunInterruptGraceful(t *testing.T) {
	if os.Getenv("TEST_RUN_INTERRUPT_CHILD") == "1" {
		cfgPath := os.Getenv("TEST_CONFIG_PATH")
		f := &flags{path: cfgPath}
		err := run(f)
		if err != nil {
			t.Fatalf("run returned error: %v", err)
		}
		return
	}

	// Prepare minimal static config with an absolute JWKS path (so the child
	// process finds the file regardless of its working directory).
	dir := t.TempDir()
	jwksPath := filepath.Join(dir, "keys.jwks")
	jwks := `{"keys":[{"kty":"oct","k":"c2VjcmV0","alg":"HS256","kid":"k1"}]}`
	require.NoError(t, os.WriteFile(jwksPath, []byte(jwks), 0o600))

	cfg := fmt.Sprintf(`
token:
  keys:
    static: %q
rules:
  - mode: allow
    when: "true"
`, jwksPath)
	cfgPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))

	cmd := exec.Command(os.Args[0], "-test.run", "^TestRunInterruptGraceful$")
	cmd.Env = append(os.Environ(),
		"TEST_RUN_INTERRUPT_CHILD=1",
		"TEST_CONFIG_PATH="+cfgPath,
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	require.NoError(t, cmd.Start())

	time.Sleep(200 * time.Millisecond)

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		require.NoError(t, err, "child output:\n%s", out.String())
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for graceful shutdown; output:\n%s", out.String())
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
