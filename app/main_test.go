package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/store"
)

func TestIntegration(t *testing.T) {
	// setup options (ensure auth is disabled for this test)
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18484" // use non-standard port to avoid conflicts
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Auth.File = ""

	// start server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(ctx)
	}()

	// wait for server to start
	waitForServer(t, "http://127.0.0.1:18484/ping")

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
	opts.Server.ReadTimeout = 5 * time.Second

	// create auth config file
	authContent := `users:
  - name: admin
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: apikey
    permissions:
      - prefix: "*"
        access: rw
  - token: readonly
    permissions:
      - prefix: "*"
        access: r
  - token: scoped
    permissions:
      - prefix: "app/*"
        access: rw
`
	authFile := filepath.Join(tmpDir, "auth.yml")
	require.NoError(t, os.WriteFile(authFile, []byte(authContent), 0o600))
	opts.Auth.File = authFile
	opts.Auth.LoginTTL = time.Hour

	// start server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(ctx)
	}()

	// wait for server to start
	waitForServer(t, "http://127.0.0.1:18485/ping")

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
		loginURL := "http://127.0.0.1:18485/login"
		resp, err := client.PostForm(loginURL, map[string][]string{"username": {"admin"}, "password": {"wrongpass"}})
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
		loginURL := "http://127.0.0.1:18485/login"
		resp, err := noRedirectClient.PostForm(loginURL, map[string][]string{"username": {"admin"}, "password": {"testpass"}})
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
		loginURL := "http://127.0.0.1:18485/login"
		resp, err := noRedirectClient.PostForm(loginURL, map[string][]string{"username": {"admin"}, "password": {"testpass"}})
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

	t.Run("logout clears session", func(t *testing.T) {
		noRedirectClient := &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		// login first
		loginURL := "http://127.0.0.1:18485/login"
		resp, err := noRedirectClient.PostForm(loginURL, map[string][]string{"username": {"admin"}, "password": {"testpass"}})
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)

		var authCookie *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "stash-auth" || c.Name == "__Host-stash-auth" {
				authCookie = c
				break
			}
		}
		require.NotNil(t, authCookie)

		// logout
		req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:18485/logout", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(authCookie)
		resp, err = noRedirectClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Equal(t, "/login", resp.Header.Get("Location"))

		// verify session is invalid - using old cookie should redirect to login
		req, err = http.NewRequest(http.MethodGet, "http://127.0.0.1:18485/", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(authCookie)
		resp, err = noRedirectClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
		assert.Equal(t, "/login", resp.Header.Get("Location"))
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
	opts.Auth.File = ""
}

func TestIntegration_WithUserPermissions(t *testing.T) {
	// setup options with auth enabled - multiple users with different permissions
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18489"
	opts.Server.ReadTimeout = 5 * time.Second

	// create auth config with scoped and readonly users
	authContent := `users:
  - name: admin
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
  - name: readonly
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: r
  - name: scoped
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "app/*"
        access: rw
tokens:
  - token: setup-token
    permissions:
      - prefix: "*"
        access: rw
`
	authFile := filepath.Join(tmpDir, "auth.yml")
	require.NoError(t, os.WriteFile(authFile, []byte(authContent), 0o600))
	opts.Auth.File = authFile
	opts.Auth.LoginTTL = time.Hour

	// start server
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(ctx)
	}()

	waitForServer(t, "http://127.0.0.1:18489/ping")

	client := &http.Client{Timeout: 5 * time.Second}
	noRedirectClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// setup test data using API token
	setupKeys := []struct {
		key   string
		value string
	}{
		{"app/config", "app-config-value"},
		{"app/db", "app-db-value"},
		{"other/secret", "secret-value"},
	}
	for _, k := range setupKeys {
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18489/kv/"+k.key, bytes.NewBufferString(k.value))
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer setup-token")
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// helper to login and get cookie
	loginUser := func(username string) *http.Cookie {
		resp, err := noRedirectClient.PostForm("http://127.0.0.1:18489/login",
			map[string][]string{"username": {username}, "password": {"testpass"}})
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusSeeOther, resp.StatusCode)
		for _, c := range resp.Cookies() {
			if c.Name == "stash-auth" || c.Name == "__Host-stash-auth" {
				return c
			}
		}
		t.Fatalf("no auth cookie for user %s", username)
		return nil
	}

	t.Run("scoped user sees only allowed keys in web UI", func(t *testing.T) {
		cookie := loginUser("scoped")

		// get key list page
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18489/web/keys", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(cookie)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		bodyStr := string(body)

		// should see app/* keys
		assert.Contains(t, bodyStr, "app/config")
		assert.Contains(t, bodyStr, "app/db")
		// should NOT see other/* keys
		assert.NotContains(t, bodyStr, "other/secret")
	})

	t.Run("scoped user cannot view key outside prefix", func(t *testing.T) {
		cookie := loginUser("scoped")

		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18489/web/keys/view/other/secret", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(cookie)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("scoped user cannot create key outside prefix", func(t *testing.T) {
		cookie := loginUser("scoped")

		formData := "key=other/newkey&value=val"
		req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:18489/web/keys", bytes.NewBufferString(formData))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(cookie)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode) // returns form with error message
		body, _ := io.ReadAll(resp.Body)
		assert.Contains(t, string(body), "Access denied")
	})

	t.Run("readonly user cannot access new key form", func(t *testing.T) {
		cookie := loginUser("readonly")

		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18489/web/keys/new", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(cookie)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("readonly user cannot edit key", func(t *testing.T) {
		cookie := loginUser("readonly")

		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18489/web/keys/edit/app/config", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(cookie)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("readonly user cannot delete key", func(t *testing.T) {
		cookie := loginUser("readonly")

		req, err := http.NewRequest(http.MethodDelete, "http://127.0.0.1:18489/web/keys/app/config", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(cookie)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("readonly user can view keys", func(t *testing.T) {
		cookie := loginUser("readonly")

		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18489/web/keys/view/app/config", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(cookie)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "app-config-value")
	})

	t.Run("admin user has full access", func(t *testing.T) {
		cookie := loginUser("admin")

		// can see all keys
		req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1:18489/web/keys", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(cookie)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Contains(t, string(body), "app/config")
		assert.Contains(t, string(body), "other/secret")

		// can access new key form
		req, err = http.NewRequest(http.MethodGet, "http://127.0.0.1:18489/web/keys/new", http.NoBody)
		require.NoError(t, err)
		req.AddCookie(cookie)
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

	// reset auth opts
	opts.Auth.File = ""
}

func waitForServer(t *testing.T, url string) {
	t.Helper()
	client := &http.Client{Timeout: 100 * time.Millisecond}
	require.Eventually(t, func() bool {
		resp, err := client.Get(url)
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 50*time.Millisecond, "server did not start")
}

func TestSetupLogs(t *testing.T) {
	t.Run("default mode", func(t *testing.T) {
		setupLogs(false) // should not panic
	})

	t.Run("debug mode", func(t *testing.T) {
		setupLogs(true) // should not panic
	})
}

func TestRun_InvalidDB(t *testing.T) {
	opts.DB = "/nonexistent/path/to/db.db"
	opts.Server.Address = "127.0.0.1:18486"
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Auth.File = ""

	err := runServer(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize store")
}

func TestRun_InvalidAuthFile(t *testing.T) {
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18487"
	opts.Server.ReadTimeout = 5 * time.Second

	// create invalid auth config file (no users or tokens)
	authFile := filepath.Join(tmpDir, "auth.yml")
	require.NoError(t, os.WriteFile(authFile, []byte("users: []\ntokens: []\n"), 0o600))
	opts.Auth.File = authFile

	err := runServer(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize server")

	// reset
	opts.Auth.File = ""
}

func TestRun_InvalidAuthFileSchema(t *testing.T) {
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18488"
	opts.Server.ReadTimeout = 5 * time.Second

	// create auth config with invalid access value (schema validation)
	invalidConfig := `users:
  - name: admin
    password: hash
    permissions:
      - prefix: "*"
        access: invalid
`
	authFile := filepath.Join(tmpDir, "auth.yml")
	require.NoError(t, os.WriteFile(authFile, []byte(invalidConfig), 0o600))
	opts.Auth.File = authFile

	err := runServer(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config validation failed")
	assert.Contains(t, err.Error(), "value must be one of")

	// reset
	opts.Auth.File = ""
}

func TestSignals(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// verify signals() doesn't panic
	require.NotPanics(t, func() {
		signals(cancel)
	})
}

func TestSighupHandler(t *testing.T) {
	var reloadCalled atomic.Bool
	reload := func(ctx context.Context) error {
		reloadCalled.Store(true)
		return nil
	}

	sighupHandler(t.Context(), reload)

	// send SIGHUP to current process
	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGHUP))

	// verify reload was called
	require.Eventually(t, reloadCalled.Load, time.Second, 10*time.Millisecond)
}

func TestSighupHandler_ReloadError(t *testing.T) {
	var reloadCalls atomic.Int32
	reload := func(ctx context.Context) error {
		reloadCalls.Add(1)
		return errors.New("reload failed")
	}

	sighupHandler(t.Context(), reload)

	// send SIGHUP - error should be logged but handler continues
	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGHUP))
	require.Eventually(t, func() bool { return reloadCalls.Load() >= 1 }, time.Second, 10*time.Millisecond)

	// send another SIGHUP - handler should still work after error
	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGHUP))
	require.Eventually(t, func() bool { return reloadCalls.Load() >= 2 }, time.Second, 10*time.Millisecond)
}

func TestValidateBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty", "", "", false},
		{"valid", "/stash", "/stash", false},
		{"valid nested", "/app/stash", "/app/stash", false},
		{"strips trailing slash", "/stash/", "/stash", false},
		{"root only", "/", "", false},
		{"missing leading slash", "stash", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateBaseURL(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIntegration_WithBaseURL(t *testing.T) {
	// setup options with base URL
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18488"
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Server.BaseURL = "/stash"
	opts.Auth.File = ""

	// start server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(ctx)
	}()

	// wait for server to start
	waitForServer(t, "http://127.0.0.1:18488/stash/ping")

	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("put and get value via base URL", func(t *testing.T) {
		// put value
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18488/stash/kv/test/key1", bytes.NewBufferString("value1"))
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// get value
		resp, err = client.Get("http://127.0.0.1:18488/stash/kv/test/key1")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		assert.Equal(t, "value1", string(body))
	})

	t.Run("base URL without trailing slash redirects", func(t *testing.T) {
		noRedirectClient := &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := noRedirectClient.Get("http://127.0.0.1:18488/stash")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusMovedPermanently, resp.StatusCode)
		assert.Equal(t, "/stash/", resp.Header.Get("Location"))
	})

	t.Run("root path returns 404", func(t *testing.T) {
		resp, err := client.Get("http://127.0.0.1:18488/kv/test")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	// shutdown
	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}

	// reset base URL for other tests
	opts.Server.BaseURL = ""
}

func TestRunRestore(t *testing.T) {
	tmpDir := t.TempDir()
	gitPath := filepath.Join(tmpDir, ".history")
	dbPath := filepath.Join(tmpDir, "test.db")

	// create git store and add some test data
	gitStore, err := git.New(git.Config{Path: gitPath, Branch: "master"})
	require.NoError(t, err)

	// commit test keys
	author := git.DefaultAuthor()
	require.NoError(t, gitStore.Commit(git.CommitRequest{Key: "app/key1", Value: []byte("value1"), Operation: "set", Author: author}))
	require.NoError(t, gitStore.Commit(git.CommitRequest{Key: "app/key2", Value: []byte("value2"), Operation: "set", Author: author}))
	require.NoError(t, gitStore.Commit(git.CommitRequest{Key: "config/db", Value: []byte("postgres://localhost"), Operation: "set", Author: author}))

	// get current HEAD commit hash
	headRef, err := gitStore.Head()
	require.NoError(t, err)

	// setup opts for restore
	opts.DB = dbPath
	opts.Git.Path = gitPath
	opts.Git.Branch = "master"
	opts.RestoreCmd.Rev = headRef

	err = runRestore(t.Context())
	require.NoError(t, err)

	// verify keys were restored to database
	kvStore, err := store.New(dbPath)
	require.NoError(t, err)
	defer kvStore.Close()

	val1, err := kvStore.Get(t.Context(), "app/key1")
	require.NoError(t, err)
	assert.Equal(t, "value1", string(val1))

	val2, err := kvStore.Get(t.Context(), "app/key2")
	require.NoError(t, err)
	assert.Equal(t, "value2", string(val2))

	val3, err := kvStore.Get(t.Context(), "config/db")
	require.NoError(t, err)
	assert.Equal(t, "postgres://localhost", string(val3))
}

func TestRunRestore_InvalidRevision(t *testing.T) {
	tmpDir := t.TempDir()
	gitPath := filepath.Join(tmpDir, ".history")

	// create git store (empty)
	_, err := git.New(git.Config{Path: gitPath, Branch: "master"})
	require.NoError(t, err)

	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Git.Path = gitPath
	opts.Git.Branch = "master"
	opts.RestoreCmd.Rev = "abc123"

	err = runRestore(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to checkout revision")
}

func TestIntegration_WithCache(t *testing.T) {
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18493"
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Auth.File = ""
	opts.Cache.Enabled = true
	opts.Cache.MaxKeys = 100

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(ctx)
	}()

	waitForServer(t, "http://127.0.0.1:18493/ping")

	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("cache serves repeated reads", func(t *testing.T) {
		// put value
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18493/kv/cached/key1", bytes.NewBufferString("cached-value"))
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// first read - populates cache
		resp, err = client.Get("http://127.0.0.1:18493/kv/cached/key1")
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, "cached-value", string(body))

		// second read - should hit cache
		resp, err = client.Get("http://127.0.0.1:18493/kv/cached/key1")
		require.NoError(t, err)
		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, "cached-value", string(body))
	})

	t.Run("cache invalidates on update", func(t *testing.T) {
		// put initial value
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18493/kv/cached/key2", bytes.NewBufferString("initial"))
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		// read to populate cache
		resp, err = client.Get("http://127.0.0.1:18493/kv/cached/key2")
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, "initial", string(body))

		// update value
		req, err = http.NewRequest(http.MethodPut, "http://127.0.0.1:18493/kv/cached/key2", bytes.NewBufferString("updated"))
		require.NoError(t, err)
		resp, err = client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		// read should return updated value (cache invalidated)
		resp, err = client.Get("http://127.0.0.1:18493/kv/cached/key2")
		require.NoError(t, err)
		body, err = io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, "updated", string(body))
	})

	t.Run("cache invalidates on delete", func(t *testing.T) {
		// put value
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18493/kv/cached/key3", bytes.NewBufferString("to-delete"))
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())

		// read to populate cache
		resp, err = client.Get("http://127.0.0.1:18493/kv/cached/key3")
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// delete
		req, err = http.NewRequest(http.MethodDelete, "http://127.0.0.1:18493/kv/cached/key3", http.NoBody)
		require.NoError(t, err)
		resp, err = client.Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusNoContent, resp.StatusCode)

		// read should return 404 (cache invalidated)
		resp, err = client.Get("http://127.0.0.1:18493/kv/cached/key3")
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	// shutdown
	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}

	// reset cache opts
	opts.Cache.Enabled = false
}

func TestRunServer_WithGit(t *testing.T) {
	tmpDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())

	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18492"
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Git.Enabled = true
	opts.Git.Path = filepath.Join(tmpDir, ".history")
	opts.Git.Branch = "master"

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(ctx)
	}()

	// wait for server to start
	waitForServer(t, "http://127.0.0.1:18492/ping")

	// shutdown
	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}

	// reset git opts
	opts.Git.Enabled = false
}

func TestIntegration_BodySizeLimit(t *testing.T) {
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18494"
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Auth.File = ""
	opts.Limits.BodySize = 100 // 100 bytes limit

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(ctx)
	}()

	waitForServer(t, "http://127.0.0.1:18494/ping")

	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("request under limit succeeds", func(t *testing.T) {
		body := bytes.NewBufferString(strings.Repeat("x", 50))
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18494/kv/small-key", body)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("request over limit returns 413", func(t *testing.T) {
		body := bytes.NewBufferString(strings.Repeat("x", 150))
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18494/kv/large-key", body)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
	})

	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}

	// reset limits
	opts.Limits.BodySize = 0
}

func TestIntegration_RateLimit(t *testing.T) {
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18495"
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Auth.File = ""
	opts.Limits.RequestsPerSec = 1 // 1 request per second for testing

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(ctx)
	}()

	waitForServer(t, "http://127.0.0.1:18495/ping")

	client := &http.Client{Timeout: 5 * time.Second}

	// make rapid requests to /kv/ endpoint - tollbooth returns 429 when rate exceeded
	codes := make([]int, 0, 10)
	for range 10 {
		resp, err := client.Get("http://127.0.0.1:18495/kv/")
		require.NoError(t, err)
		codes = append(codes, resp.StatusCode)
		_ = resp.Body.Close()
	}

	// at least one should be 429 (too many requests) from tollbooth rate limiter
	assert.True(t, slices.Contains(codes, http.StatusTooManyRequests),
		"expected at least one 429 response from rate limiter, got: %v", codes)

	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}

	// reset limits
	opts.Limits.RequestsPerSec = 0
}

func TestIntegration_MaxConcurrent(t *testing.T) {
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18497"
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Auth.File = ""
	opts.Limits.MaxConcurrent = 2       // very low for testing
	opts.Limits.RequestsPerSec = 10000  // high rate limit so it doesn't interfere

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(ctx)
	}()

	waitForServer(t, "http://127.0.0.1:18497/ping")

	client := &http.Client{Timeout: 5 * time.Second}

	t.Run("concurrent requests within limit succeed", func(t *testing.T) {
		// sequential requests should all succeed
		for range 5 {
			resp, err := client.Get("http://127.0.0.1:18497/kv/")
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, resp.StatusCode)
			_ = resp.Body.Close()
		}
	})

	t.Run("concurrent requests exceeding limit get 503", func(t *testing.T) {
		// create a slow handler by putting a large value first
		largeValue := strings.Repeat("x", 100000)
		req, err := http.NewRequest(http.MethodPut, "http://127.0.0.1:18497/kv/large", bytes.NewBufferString(largeValue))
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()

		// fire many concurrent requests
		const numRequests = 20
		var wg sync.WaitGroup
		codes := make(chan int, numRequests)

		for range numRequests {
			wg.Go(func() {
				resp, err := client.Get("http://127.0.0.1:18497/kv/large")
				if err != nil {
					codes <- 0
					return
				}
				codes <- resp.StatusCode
				_ = resp.Body.Close()
			})
		}

		wg.Wait()
		close(codes)

		results := make([]int, 0, numRequests)
		for code := range codes {
			results = append(results, code)
		}

		// with MaxConcurrent=2 and 20 concurrent requests, some should get 503
		has503 := slices.Contains(results, http.StatusServiceUnavailable)
		has200 := slices.Contains(results, http.StatusOK)
		assert.True(t, has200, "some requests should succeed, got: %v", results)
		assert.True(t, has503, "some requests should get 503 (service unavailable), got: %v", results)
	})

	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}

	// reset limits
	opts.Limits.MaxConcurrent = 0
	opts.Limits.RequestsPerSec = 0
}

func TestIntegration_LoginConcurrency(t *testing.T) {
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18496"
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Limits.LoginConcurrency = 2 // very low for testing

	// setup auth
	authContent := `users:
  - name: admin
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
`
	authFile := filepath.Join(tmpDir, "auth.yml")
	require.NoError(t, os.WriteFile(authFile, []byte(authContent), 0o600))
	opts.Auth.File = authFile
	opts.Auth.LoginTTL = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- runServer(ctx)
	}()

	waitForServer(t, "http://127.0.0.1:18496/ping")

	// start concurrent login attempts
	const numLogins = 10
	var wg sync.WaitGroup
	codes := make(chan int, numLogins)

	noRedirectClient := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	for range numLogins {
		wg.Go(func() {
			resp, err := noRedirectClient.PostForm("http://127.0.0.1:18496/login",
				map[string][]string{"username": {"admin"}, "password": {"testpass"}})
			if err != nil {
				codes <- 0 // error case
				return
			}
			codes <- resp.StatusCode
			_ = resp.Body.Close()
		})
	}

	wg.Wait()
	close(codes)

	// collect results
	results := make([]int, 0, numLogins)
	for code := range codes {
		results = append(results, code)
	}

	// some should be throttled (503 from rest.Throttle concurrent limiter)
	assert.True(t, slices.Contains(results, http.StatusServiceUnavailable),
		"expected at least one 503 response for login concurrency throttling, got: %v", results)

	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}

	// reset
	opts.Auth.File = ""
	opts.Limits.LoginConcurrency = 0
}
