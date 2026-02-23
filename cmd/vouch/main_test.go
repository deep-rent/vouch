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
	"encoding/json"
	"fmt"
	"net"
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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// binaryPath stores the path to the compiled Vouch binary used for testing.
var binaryPath string

// TestMain compiles the Vouch binary once before running all tests.
// This ensures we are testing the actual build artifact.
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
	// 1. Setup Mock JWKS Server
	// Generate a fresh RSA key pair for signing tokens.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create a JWK Set containing the public key.
	pubKey := &privKey.PublicKey
	jwkKey := jwk.NewKeyBuilder(jwa.RS256).WithKeyID("test-key").Build(pubKey)
	jwkSet := jwk.Singleton(jwkKey)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jwkSet)
	}))
	defer jwksServer.Close()

	// 2. Setup Mock Upstream (CouchDB)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that Vouch injected the proxy authentication headers.
		user := r.Header.Get("X-Auth-CouchDB-UserName")
		roles := r.Header.Get("X-Auth-CouchDB-Roles")

		if user == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("missing user header"))
			return
		}

		// Echo the headers back in the response for assertion.
		w.Header().Set("X-Received-User", user)
		w.Header().Set("X-Received-Roles", roles)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	// 3. Configure and Run Vouch
	port := getFreePort(t)
	host := "127.0.0.1"
	vouchURL := fmt.Sprintf("http://%s:%d", host, port)

	cmd := exec.Command(binaryPath)
	cmd.Env = append(os.Environ(),
		"VOUCH_KEYS_URL="+jwksServer.URL,
		"VOUCH_TARGET="+upstream.URL,
		"VOUCH_PORT="+fmt.Sprintf("%d", port),
		"VOUCH_HOST="+host,
		"VOUCH_LOG_LEVEL=debug",
		// Speed up refresh to ensure keys are loaded quickly.
		"VOUCH_KEYS_MIN_REFRESH_INTERVAL=1s",
	)

	// Capture stderr to debug potential startup failures.
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	require.NoError(t, cmd.Start())
	defer func() {
		_ = cmd.Process.Kill()
	}()

	// Wait for Vouch to start listening.
	waitForPort(t, host, port)

	// 4. Generate a Valid JWT
	signer := jwt.NewSigner(
		jwk.NewKeyBuilder(jwa.RS256).
			WithKeyID("test-key").
			BuildPair(privKey),
	)
	require.NoError(t, err)

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
		req, _ := http.NewRequest("GET", vouchURL+"/some/db", nil)
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
		"Vouch failed to proxy valid request (check logs: %s)",
		stderr.String(),
	)

	assert.Equal(t, "alice", res.Header.Get("X-Received-User"))
	assert.Equal(t, "admin,basic", res.Header.Get("X-Received-Roles"))

	// 6. Test Invalid Token
	reqInvalid, _ := http.NewRequest("GET", vouchURL+"/some/db", nil)
	reqInvalid.Header.Set("Authorization", "Bearer invalid.token.here")
	respInvalid, err := client.Do(reqInvalid)
	require.NoError(t, err)
	defer respInvalid.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, respInvalid.StatusCode)
}

func getFreePort(t *testing.T) int {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	require.NoError(t, err)
	l, err := net.ListenTCP("tcp", addr)
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitForPort(t *testing.T, host string, port int) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		return false
	},
		5*time.Second,
		100*time.Millisecond,
		"Timed out waiting for %s to be available",
		addr,
	)
}
