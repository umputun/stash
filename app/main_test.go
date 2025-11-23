package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration(t *testing.T) {
	// setup options
	tmpDir := t.TempDir()
	opts.Store = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18484" // use non-standard port to avoid conflicts
	opts.Server.ReadTimeout = 5
	opts.Log.Enabled = false

	// start server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx)
	}()

	// wait for server to start
	waitForServer(t, "http://127.0.0.1:18484/ping", 2*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("put and get value", func(t *testing.T) {
		// put value
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18484/kv/test/key1", bytes.NewBufferString("value1"))
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// get value
		resp, err = client.Get("http://127.0.0.1:18484/kv/test/key1")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "value1", string(body))
	})

	t.Run("get nonexistent key returns 404", func(t *testing.T) {
		resp, err := client.Get("http://127.0.0.1:18484/kv/nonexistent")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("delete key", func(t *testing.T) {
		// put value first
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18484/kv/todelete", bytes.NewBufferString("temp"))
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		// delete
		req, err = http.NewRequest(http.MethodDelete, "http://127.0.0.1:18484/kv/todelete", http.NoBody)
		require.NoError(t, err)
		resp, err = client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		// verify deleted
		resp, err = client.Get("http://127.0.0.1:18484/kv/todelete")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("binary data", func(t *testing.T) {
		binary := []byte{0x00, 0x01, 0xFF, 0xFE}
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18484/kv/binary", bytes.NewBuffer(binary))
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		resp, err = client.Get("http://127.0.0.1:18484/kv/binary")
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, binary, body)
	})

	// shutdown
	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func waitForServer(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close() // ignore error in polling loop
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server did not start within %v", timeout)
}
