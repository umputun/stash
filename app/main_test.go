package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIntegration(t *testing.T) {
	// setup options (ensure auth is disabled for this test)
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18484" // use non-standard port to avoid conflicts
	opts.Server.ReadTimeout = 5
	opts.Auth.PasswordHash = ""
	opts.Auth.Tokens = nil
	opts.Discovery.TTLCheckInterval = 5
	opts.Discovery.HTTPCheckInterval = 10
	opts.Discovery.HTTPCheckTimeout = 5

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

func TestIntegration_WithAuth(t *testing.T) {
	// setup options with auth enabled
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18485"
	opts.Server.ReadTimeout = 5
	// bcrypt hash for "testpass"
	opts.Auth.PasswordHash = "$2a$10$kE1cSYqrktsr5iVW2pbB3OOmZAgGRggfXbvs/q0XUpyqvzLywEQ5y"
	opts.Auth.Tokens = []string{"apikey:*:rw", "readonly:*:r", "scoped:app/*:rw"}
	opts.Auth.LoginTTL = 60
	opts.Discovery.TTLCheckInterval = 5
	opts.Discovery.HTTPCheckInterval = 10
	opts.Discovery.HTTPCheckTimeout = 5

	// start server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx)
	}()

	// wait for server to start
	waitForServer(t, "http://127.0.0.1:18485/ping", 2*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("api without token returns 401", func(t *testing.T) {
		resp, err := client.Get("http://127.0.0.1:18485/kv/test")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("api with invalid token returns 401", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18485/kv/test", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer invalid")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("api with valid rw token can read and write", func(t *testing.T) {
		// write
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18485/kv/authtest", bytes.NewBufferString("authvalue"))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer apikey")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// read
		req, err = http.NewRequest(http.MethodGet, "http://127.0.0.1:18485/kv/authtest", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer apikey")
		resp, err = client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "authvalue", string(body))
	})

	t.Run("api with readonly token can read but not write", func(t *testing.T) {
		// read should work
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18485/kv/authtest", http.NoBody)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer readonly")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// write should fail
		req, err = http.NewRequest(http.MethodPut, "http://127.0.0.1:18485/kv/readonly-test", bytes.NewBufferString("value"))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer readonly")
		resp, err = client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("api with scoped token respects prefix", func(t *testing.T) {
		// can write to app/*
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18485/kv/app/config", bytes.NewBufferString("appvalue"))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer scoped")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// cannot write to other/*
		req, err = http.NewRequest(http.MethodPut, "http://127.0.0.1:18485/kv/other/key", bytes.NewBufferString("value"))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer scoped")
		resp, err = client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("web ui redirects to login", func(t *testing.T) {
		// disable redirects to check the redirect response
		noRedirectClient := &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := noRedirectClient.Get("http://127.0.0.1:18485/")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Equal(t, "/login", resp.Header.Get("Location"))
	})

	t.Run("login with wrong password fails", func(t *testing.T) {
		resp, err := client.PostForm("http://127.0.0.1:18485/login", map[string][]string{"password": {"wrongpass"}})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("login with correct password sets cookie", func(t *testing.T) {
		noRedirectClient := &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := noRedirectClient.PostForm("http://127.0.0.1:18485/login", map[string][]string{"password": {"testpass"}})
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Equal(t, "/", resp.Header.Get("Location"))

		// check for auth cookie
		var authCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "stash-auth" || c.Name == "__Host-stash-auth" {
				authCookie = c
				break
			}
		}
		require.NotNil(t, authCookie, "auth cookie should be set")
		assert.True(t, authCookie.HttpOnly)
	})

	t.Run("session cookie allows api access", func(t *testing.T) {
		// login first
		noRedirectClient := &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := noRedirectClient.PostForm("http://127.0.0.1:18485/login", map[string][]string{"password": {"testpass"}})
		require.NoError(t, err)
		defer resp.Body.Close()

		// get cookie
		var authCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "stash-auth" || c.Name == "__Host-stash-auth" {
				authCookie = c
				break
			}
		}
		require.NotNil(t, authCookie)

		// use cookie for api call
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18485/kv/authtest", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(authCookie)
		resp, err = client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// shutdown
	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}

	// reset auth opts for other tests
	opts.Auth.PasswordHash = ""
	opts.Auth.Tokens = nil
}

func TestIntegration_ServiceDiscovery(t *testing.T) {
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18486"
	opts.Server.ReadTimeout = 5
	opts.Auth.PasswordHash = ""
	opts.Auth.Tokens = nil
	opts.Discovery.TTLCheckInterval = 5
	opts.Discovery.HTTPCheckInterval = 10
	opts.Discovery.HTTPCheckTimeout = 5

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- run(ctx)
	}()

	waitForServer(t, "http://127.0.0.1:18486/ping", 2*time.Second)

	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("register and discover service", func(t *testing.T) {
		// register service
		body := `{"address":"10.0.0.1","port":8080,"tags":["primary"],"check":{"type":"ttl","ttl":60}}`
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18486/service/api", bytes.NewBufferString(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// parse response to get ID
		var regResp struct {
			ID string `json:"id"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&regResp))
		assert.Contains(t, regResp.ID, "svc-")

		// discover service
		resp, err = client.Get("http://127.0.0.1:18486/service/api")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var services []struct {
			ID      string   `json:"id"`
			Name    string   `json:"name"`
			Address string   `json:"address"`
			Port    int      `json:"port"`
			Tags    []string `json:"tags"`
			Healthy bool     `json:"healthy"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&services))
		require.Len(t, services, 1)
		assert.Equal(t, regResp.ID, services[0].ID)
		assert.Equal(t, "api", services[0].Name)
		assert.Equal(t, "10.0.0.1", services[0].Address)
		assert.Equal(t, 8080, services[0].Port)
		assert.True(t, services[0].Healthy)
	})

	t.Run("send heartbeat", func(t *testing.T) {
		// first register a service
		body := `{"id":"heartbeat-svc","address":"10.0.0.2","port":9090,"check":{"type":"ttl","ttl":60}}`
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18486/service/worker", bytes.NewBufferString(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		// send heartbeat
		req, err = http.NewRequest(http.MethodPut, "http://127.0.0.1:18486/service/worker/heartbeat-svc/health", http.NoBody)
		require.NoError(t, err)
		resp, err = client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("deregister service", func(t *testing.T) {
		// register
		body := `{"id":"to-delete","address":"10.0.0.3","port":7070}`
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18486/service/temp", bytes.NewBufferString(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		// deregister
		req, err = http.NewRequest(http.MethodDelete, "http://127.0.0.1:18486/service/temp/to-delete", http.NoBody)
		require.NoError(t, err)
		resp, err = client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		// verify gone
		resp, err = client.Get("http://127.0.0.1:18486/service/temp")
		require.NoError(t, err)
		defer resp.Body.Close()
		var services []interface{}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&services))
		assert.Empty(t, services)
	})

	t.Run("list all services", func(t *testing.T) {
		resp, err := client.Get("http://127.0.0.1:18486/services")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var summaries []struct {
			Name      string `json:"name"`
			Instances int    `json:"instances"`
			Healthy   int    `json:"healthy"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&summaries))
		// should have api and worker from previous tests
		assert.GreaterOrEqual(t, len(summaries), 2)
	})

	t.Run("filter by tags", func(t *testing.T) {
		resp, err := client.Get("http://127.0.0.1:18486/service/api?tag=primary")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var services []struct {
			Tags []string `json:"tags"`
		}
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&services))
		if len(services) > 0 {
			assert.Contains(t, services[0].Tags, "primary")
		}
	})

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
