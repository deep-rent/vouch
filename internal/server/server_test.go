package server_test

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/deep-rent/vouch/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServer_Lifecycle(t *testing.T) {
	// Find a free port
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	_, port, err := net.SplitHostPort(l.Addr().String())
	require.NoError(t, err)
	l.Close()

	// Configure Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	cfg := &server.Config{
		Handler:           handler,
		Host:              "127.0.0.1",
		Port:              port,
		ReadHeaderTimeout: 1 * time.Second,
		ReadTimeout:       1 * time.Second,
		WriteTimeout:      1 * time.Second,
		IdleTimeout:       1 * time.Second,
		MaxHeaderBytes:    1024,
		Logger:            slog.Default(),
	}

	srv := server.New(cfg)

	// Launch server in background
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	baseURL := fmt.Sprintf("http://127.0.0.1:%s", port)

	// Wait for readiness
	require.Eventually(t, func() bool {
		res, err := http.Get(baseURL)
		if err != nil {
			return false
		}
		res.Body.Close()
		return res.StatusCode == http.StatusOK
	}, 2*time.Second, 50*time.Millisecond, "Server failed to start")

	// Verify handler
	res, err := http.Get(baseURL)
	require.NoError(t, err)
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	assert.Equal(t, "ok", string(body))

	// Stop server
	err = srv.Stop()
	require.NoError(t, err)

	// Verify shutdown
	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, http.ErrServerClosed)
	case <-time.After(2 * time.Second):
		t.Fatal("Server did not return from Start() after Stop()")
	}
}
