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

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/store"
)

func TestIntegration(t *testing.T) {
	// setup options (ensure auth is disabled for this test)
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18484" // use non-standard port to avoid conflicts
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Auth.PasswordHash = ""
	opts.Auth.Tokens = nil

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
	// bcrypt hash for "testpass"
	opts.Auth.PasswordHash = "$2a$10$kE1cSYqrktsr5iVW2pbB3OOmZAgGRggfXbvs/q0XUpyqvzLywEQ5y"
	opts.Auth.Tokens = []string{"apikey:*:rw", "readonly:*:r", "scoped:app/*:rw"}
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
		w := setupLogs(false)
		assert.NotNil(t, w)
	})

	t.Run("debug mode", func(t *testing.T) {
		w := setupLogs(true)
		assert.NotNil(t, w)
	})
}

func TestRun_InvalidDB(t *testing.T) {
	opts.DB = "/nonexistent/path/to/db.db"
	opts.Server.Address = "127.0.0.1:18486"
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Auth.PasswordHash = ""
	opts.Auth.Tokens = nil

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := runServer(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize store")
}

func TestRun_InvalidAuthToken(t *testing.T) {
	tmpDir := t.TempDir()
	opts.DB = filepath.Join(tmpDir, "test.db")
	opts.Server.Address = "127.0.0.1:18487"
	opts.Server.ReadTimeout = 5 * time.Second
	opts.Auth.PasswordHash = "$2a$10$hash"
	opts.Auth.Tokens = []string{"invalid"} // invalid token format

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := runServer(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize server")

	// reset
	opts.Auth.PasswordHash = ""
	opts.Auth.Tokens = nil
}

func TestSignals(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	// verify signals() doesn't panic
	require.NotPanics(t, func() {
		signals(cancel)
	})
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
	opts.Auth.PasswordHash = ""
	opts.Auth.Tokens = nil

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
	require.NoError(t, gitStore.Commit("app/key1", []byte("value1"), "set"))
	require.NoError(t, gitStore.Commit("app/key2", []byte("value2"), "set"))
	require.NoError(t, gitStore.Commit("config/db", []byte("postgres://localhost"), "set"))

	// get current HEAD commit hash
	headRef, err := gitStore.Head()
	require.NoError(t, err)

	// setup opts for restore
	opts.DB = dbPath
	opts.Git.Path = gitPath
	opts.Git.Branch = "master"
	opts.RestoreCmd.Rev = headRef

	err = runRestore()
	require.NoError(t, err)

	// verify keys were restored to database
	kvStore, err := store.New(dbPath)
	require.NoError(t, err)
	defer kvStore.Close()

	val1, err := kvStore.Get("app/key1")
	require.NoError(t, err)
	assert.Equal(t, "value1", string(val1))

	val2, err := kvStore.Get("app/key2")
	require.NoError(t, err)
	assert.Equal(t, "value2", string(val2))

	val3, err := kvStore.Get("config/db")
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

	err = runRestore()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to checkout revision")
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
