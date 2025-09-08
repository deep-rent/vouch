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

// writeConfig creates a minimal valid config containing a static JWKS.
func writeConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	jwksPath := filepath.Join(dir, "jwks.json")
	jwks := `{"keys":[{"kty":"oct","k":"c2VjcmV0","alg":"HS256","kid":"k1"}]}`
	require.NoError(t, os.WriteFile(jwksPath, []byte(jwks), 0o600))

	cfg := fmt.Sprintf(`
guard:
  token:
    keys:
      static: %q
  rules:
    - mode: allow
      when: "true"
`, jwksPath)
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))
	return path
}

func TestParse(t *testing.T) {
	orig := os.Args
	defer func() { os.Args = orig }()

	cases := []struct {
		name string
		args []string
		env  string
		want flags
	}{
		{"default path", []string{"vouch"}, "", flags{path: "./config.yaml"}},
		{"environment variable overrides default", []string{"vouch"}, "env.yaml", flags{path: "env.yaml"}},
		{"short flag overrides environment variable", []string{"vouch", "-c", "arg.yaml"}, "env.yaml", flags{path: "arg.yaml"}},
		{"long flag overrides environment variable", []string{"vouch", "--config", "arg.yaml"}, "env.yaml", flags{path: "arg.yaml"}},
		{"long flag with equals overrides environment variable", []string{"vouch", "--config=arg.yaml"}, "env.yaml", flags{path: "arg.yaml"}},
		{"short version flag", []string{"vouch", "-v"}, "", flags{path: "./config.yaml", version: true}},
		{"long version flag", []string{"vouch", "--version"}, "", flags{path: "./config.yaml", version: true}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			os.Args = tc.args
			if tc.env != "" {
				t.Setenv("VOUCH_CONFIG", tc.env)
			} else {
				os.Unsetenv("VOUCH_CONFIG")
			}
			f, err := parse()
			require.NoError(t, err)
			assert.Equal(t, tc.want.path, f.path)
			assert.Equal(t, tc.want.version, f.version)
		})
	}
}

func TestRunConfigLoadError(t *testing.T) {
	f := &flags{path: "does-not-exist.yaml"}
	err := run(f)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "couldn't load config")
}

// TestRunInterruptGraceful runs main logic in a subprocess and sends SIGTERM,
// exercising the graceful shutdown branch without synthetic seams.
func TestRunInterruptGraceful(t *testing.T) {
	if os.Getenv("TEST_RUN_INTERRUPT_CHILD") == "1" {
		f := &flags{path: os.Getenv("TEST_CONFIG_PATH")}
		if err := run(f); err != nil {
			t.Fatalf("run returned error: %v", err)
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^TestRunInterruptGraceful$")
	cmd.Env = append(os.Environ(),
		"TEST_RUN_INTERRUPT_CHILD=1",
		"TEST_CONFIG_PATH="+writeConfig(t),
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	require.NoError(t, cmd.Start())

	// Sleep instead of polling output to avoid data race.
	time.Sleep(200 * time.Millisecond)

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		// Safe: buffer no longer written to.
		require.NoError(t, err, "child output:\n%s", out.String())
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for graceful shutdown; output:\n%s", out.String())
	}
}

func TestMainVersionFlag(t *testing.T) {
	if os.Getenv("TEST_MAIN_VERSION") == "1" {
		os.Args = []string{"vouch", "-v"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run", "TestMainVersionFlag")
	cmd.Env = append(os.Environ(), "TEST_MAIN_VERSION=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	require.NoError(t, cmd.Run())
	assert.Contains(t, out.String(), "version:")
}
