// Copyright (c) 2025-present deep.rent GmbH (https://deep.rent)
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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/deep-rent/nexus/jose/jwa"
	"github.com/deep-rent/nexus/jose/jwk"
	"github.com/deep-rent/nexus/jose/jwt"
	"github.com/deep-rent/nexus/testutil/ports"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// binaryPath stores the path to the compiled vouch binary used for testing.
var binaryPath string

// TestMain compiles the vouch binary once before running all tests.
// this ensures we are testing the actual build artifact.
func TestMain(m *testing.M) {
	// Create a temporary directory for the build artifact.
	tmpDir, err := os.MkdirTemp("", "vouch-build")
	if err != nil {
		panic(fmt.Sprintf("failed to create temp dir: %v", err))
	}
	defer os.RemoveAll(tmpDir)

	binaryPath = filepath.Join(tmpDir, "vouch")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}

	// Build the binary from the current directory (cmd/vouch).
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building vouch failed: %v\n%s\n", err, out)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestVersion(t *testing.T) {
	cmd := exec.Command(binaryPath, "-v")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err)
	assert.Contains(t, string(out), "dev", "output should contain the version")
}

func TestMissingConfig(t *testing.T) {
	cmd := exec.Command(binaryPath)
	// Clear environment variables to ensure required config is missing.
	cmd.Env = []string{}
	out, err := cmd.CombinedOutput()

	// The process should fail.
	assert.Error(t, err)
	assert.Contains(t, string(out),
		"required variable \"VOUCH_KEYS_URL\" is not set",
	)
}

func TestIntegration(t *testing.T) {
	// 1. setup mock jwks server.
	// generate a fresh RSA key pair for signing tokens.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// create a jwk set containing the public key.
	pub := &key.PublicKey
	k := jwk.NewKeyBuilder(jwa.RS256).WithKeyID("test-key").Build(pub)
	set := jwk.Singleton(k)

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, err := jwk.WriteSet(set)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = w.Write(data)
	}))
	defer jwks.Close()

	// 2. setup mock upstream (couchdb).
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// verify that vouch injected the proxy authentication headers.
		user := r.Header.Get("X-Auth-CouchDB-UserName")
		roles := r.Header.Get("X-Auth-CouchDB-Roles")

		if user == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("missing user header"))
			return
		}

		// echo the headers back in the response for assertion.
		w.Header().Set("X-Received-User", user)
		w.Header().Set("X-Received-Roles", roles)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer backend.Close()

	// 3. configure and run vouch.
	port := ports.FreeT(t)
	host := "127.0.0.1"
	vouch := fmt.Sprintf("http://%s:%d", host, port)

	cmd := exec.Command(binaryPath)
	cmd.Env = append(os.Environ(),
		"VOUCH_KEYS_URL="+jwks.URL,
		"VOUCH_TARGET="+backend.URL,
		"VOUCH_PORT="+fmt.Sprintf("%d", port),
		"VOUCH_HOST="+host,
		"VOUCH_LOG_LEVEL=debug",
		// speed up refresh to ensure keys are loaded quickly.
		"VOUCH_KEYS_MIN_REFRESH_INTERVAL=1",
	)

	// capture stderr to debug potential startup failures.
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
	}()

	ports.WaitT(t, host, port)

	// 4. Generate a Valid JWT
	signer := jwt.NewSigner(
		jwk.NewKeyBuilder(jwa.RS256).
			WithKeyID("test-key").
			BuildPair(key),
	)

	// payload := map[string]any{
	// 	"sub":            "alice",
	// 	"_couchdb.roles": []string{"admin", "basic"},
	// }

	type Claims struct {
		jwt.Reserved
		Roles []string `json:"_couchdb.roles"`
	}

	payload := &Claims{
		Reserved: jwt.Reserved{Sub: "alice"},
		Roles:    []string{"admin", "basic"},
	}
	token, err := signer.Sign(payload)
	require.NoError(t, err)

	// We retry a few times to allow the Bouncer to fetch the JWKS in the
	// background.
	client := &http.Client{Timeout: 5 * time.Second}
	var res *http.Response

	require.Eventually(t, func() bool {
		req, _ := http.NewRequest("GET", vouch+"/some/db", nil)
		req.Header.Set("Authorization", "Bearer "+string(token))

		res, err = client.Do(req)
		if err != nil {
			return false
		}
		defer res.Body.Close()
		return res.StatusCode == http.StatusOK
	},
		5*time.Second,
		200*time.Millisecond,
		"Vouch failed to proxy valid request (check logs: %s\n%s)",
		stderr.String(),
		stdout.String(),
	)

	assert.Equal(t, "alice", res.Header.Get("X-Received-User"))
	assert.Equal(t, "admin,basic", res.Header.Get("X-Received-Roles"))

	// 6. test invalid token.
	reqInvalid, _ := http.NewRequest("GET", vouch+"/some/db", nil)
	reqInvalid.Header.Set("Authorization", "Bearer invalid.token.here")
	respInvalid, err := client.Do(reqInvalid)
	require.NoError(t, err)
	defer respInvalid.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, respInvalid.StatusCode)
}
