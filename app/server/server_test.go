package server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/mocks"
	"github.com/umputun/stash/app/store"
	"github.com/umputun/stash/app/validator"
)

func TestServer_HandleGet(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			switch key {
			case "testkey":
				return []byte("testvalue"), "text", nil
			case "path/to/key":
				return []byte("nested value"), "text", nil
			default:
				return nil, "", store.ErrNotFound
			}
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	t.Run("get existing key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/testkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "testvalue", rec.Body.String())
		assert.Equal(t, "text/plain", rec.Header().Get("Content-Type"))
	})

	t.Run("get nonexistent key returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/nonexistent", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("get key with slashes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/path/to/key", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "nested value", rec.Body.String())
	})
}

func TestServer_HandleGet_ContentType(t *testing.T) {
	tbl := []struct {
		format, contentType string
	}{
		{"json", "application/json"},
		{"yaml", "application/yaml"},
		{"xml", "application/xml"},
		{"toml", "application/toml"},
		{"hcl", "text/plain"},
		{"ini", "text/plain"},
		{"shell", "text/x-shellscript"},
		{"text", "text/plain"},
		{"", "application/octet-stream"},
	}

	for _, tc := range tbl {
		t.Run(tc.format, func(t *testing.T) {
			st := &mocks.KVStoreMock{
				GetWithFormatFunc: func(key string) ([]byte, string, error) { return []byte("value"), tc.format, nil },
				ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
			}
			srv := newTestServer(t, st)

			req := httptest.NewRequest(http.MethodGet, "/kv/testkey", http.NoBody)
			rec := httptest.NewRecorder()
			srv.routes().ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, tc.contentType, rec.Header().Get("Content-Type"))
		})
	}
}

func TestServer_HandleSet(t *testing.T) {
	t.Run("set new key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return nil },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		body := bytes.NewBufferString("newvalue")
		req := httptest.NewRequest(http.MethodPut, "/kv/newkey", body)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "newkey", st.SetCalls()[0].Key)
		assert.Equal(t, []byte("newvalue"), st.SetCalls()[0].Value)
	})

	t.Run("update existing key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return nil },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		body := bytes.NewBufferString("updated")
		req := httptest.NewRequest(http.MethodPut, "/kv/existing", body)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "existing", st.SetCalls()[0].Key)
		assert.Equal(t, []byte("updated"), st.SetCalls()[0].Value)
	})

	t.Run("set key with slashes", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return nil },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		body := bytes.NewBufferString("nested")
		req := httptest.NewRequest(http.MethodPut, "/kv/a/b/c", body)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "a/b/c", st.SetCalls()[0].Key)
		assert.Equal(t, []byte("nested"), st.SetCalls()[0].Value)
	})

	t.Run("valid format via header", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return nil },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		body := bytes.NewBufferString(`{"key": "value"}`)
		req := httptest.NewRequest(http.MethodPut, "/kv/config", body)
		req.Header.Set("X-Stash-Format", "json")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "json", st.SetCalls()[0].Format)
	})

	t.Run("valid format via query param", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return nil },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		body := bytes.NewBufferString("key: value")
		req := httptest.NewRequest(http.MethodPut, "/kv/config?format=yaml", body)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "yaml", st.SetCalls()[0].Format)
	})

	t.Run("invalid format defaults to text", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return nil },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		body := bytes.NewBufferString("value")
		req := httptest.NewRequest(http.MethodPut, "/kv/config", body)
		req.Header.Set("X-Stash-Format", "invalid-format")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "text", st.SetCalls()[0].Format)
	})

	t.Run("empty format defaults to text", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return nil },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		body := bytes.NewBufferString("value")
		req := httptest.NewRequest(http.MethodPut, "/kv/config", body)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "text", st.SetCalls()[0].Format)
	})
}

func TestServer_HandleDelete(t *testing.T) {
	t.Run("delete existing key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodDelete, "/kv/todelete", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		require.Len(t, st.DeleteCalls(), 1)
		assert.Equal(t, "todelete", st.DeleteCalls()[0].Key)
	})

	t.Run("delete nonexistent key returns 404", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return store.ErrNotFound },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodDelete, "/kv/nonexistent", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
		require.Len(t, st.DeleteCalls(), 1)
		assert.Equal(t, "nonexistent", st.DeleteCalls()[0].Key)
	})
}

func TestServer_Ping(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	req := httptest.NewRequest(http.MethodGet, "/ping", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "pong", rec.Body.String())
}

func TestServer_HandleGet_InternalError(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) { return nil, "", errors.New("db error") },
		ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	req := httptest.NewRequest(http.MethodGet, "/kv/testkey", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Len(t, st.GetWithFormatCalls(), 1)
	assert.Equal(t, "testkey", st.GetWithFormatCalls()[0].Key)
}

func TestServer_HandleSet_InternalError(t *testing.T) {
	st := &mocks.KVStoreMock{
		SetFunc:  func(key string, value []byte, format string) error { return errors.New("db error") },
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	body := bytes.NewBufferString("value")
	req := httptest.NewRequest(http.MethodPut, "/kv/testkey", body)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Len(t, st.SetCalls(), 1)
	assert.Equal(t, "testkey", st.SetCalls()[0].Key)
}

func TestServer_HandleDelete_InternalError(t *testing.T) {
	st := &mocks.KVStoreMock{
		DeleteFunc: func(key string) error { return errors.New("db error") },
		ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	req := httptest.NewRequest(http.MethodDelete, "/kv/testkey", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Len(t, st.DeleteCalls(), 1)
	assert.Equal(t, "testkey", st.DeleteCalls()[0].Key)
}

func TestServer_New_InvalidTokens(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	_, err := New(st, validator.NewService(), nil, Config{
		Address:     ":8080",
		ReadTimeout: 5 * time.Second,
		AuthFile:    "/nonexistent/auth.yml", // file doesn't exist
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize auth")
}

func TestServer_Handler_BaseURL(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			if key == "testkey" {
				return []byte("testvalue"), "text", nil
			}
			return nil, "", store.ErrNotFound
		},
		SetFunc:  func(key string, value []byte, format string) error { return nil },
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}

	t.Run("without base URL routes work at root", func(t *testing.T) {
		cfg := Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", BaseURL: ""}
		srv, err := New(st, validator.NewService(), nil, cfg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/kv/testkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "testvalue", rec.Body.String())
	})

	t.Run("with base URL routes work under prefix", func(t *testing.T) {
		cfg := Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", BaseURL: "/stash"}
		srv, err := New(st, validator.NewService(), nil, cfg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/stash/kv/testkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "testvalue", rec.Body.String())
	})

	t.Run("base URL redirects to trailing slash", func(t *testing.T) {
		cfg := Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", BaseURL: "/stash"}
		srv, err := New(st, validator.NewService(), nil, cfg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/stash", http.NoBody)
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusMovedPermanently, rec.Code)
		assert.Equal(t, "/stash/", rec.Header().Get("Location"))
	})

	t.Run("with base URL root path still accessible via prefix", func(t *testing.T) {
		cfg := Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", BaseURL: "/stash"}
		srv, err := New(st, validator.NewService(), nil, cfg)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/stash/ping", http.NoBody)
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "pong", rec.Body.String())
	})

	t.Run("with base URL set correctly passes to KV API", func(t *testing.T) {
		cfg := Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", BaseURL: "/app/stash"}
		srv, err := New(st, validator.NewService(), nil, cfg)
		require.NoError(t, err)

		body := bytes.NewBufferString("newvalue")
		req := httptest.NewRequest(http.MethodPut, "/app/stash/kv/newkey", body)
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "newkey", st.SetCalls()[0].Key)
	})
}

func newTestServer(t *testing.T, st KVStore) *Server {
	t.Helper()
	srv, err := New(st, validator.NewService(), nil, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test"})
	require.NoError(t, err)
	return srv
}

func TestServer_AuthHotReload(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := tmpDir + "/auth.yml"
	// bcrypt hash for "testpass"
	authConfig := `users:
  - name: "admin"
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
`
	require.NoError(t, os.WriteFile(authFile, []byte(authConfig), 0o600))

	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv, err := New(st, validator.NewService(), nil, Config{
		Address: ":0", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile, AuthHotReload: true,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// run server in background
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	// give server and watcher time to start (watcher starts before HTTP server)
	time.Sleep(100 * time.Millisecond)

	// create session for original user
	sessionToken, err := srv.auth.CreateSession("admin")
	require.NoError(t, err)
	assert.NotEmpty(t, sessionToken)

	// update auth file with new user
	newAuthConfig := `users:
  - name: "newuser"
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
`
	require.NoError(t, os.WriteFile(authFile, []byte(newAuthConfig), 0o600))

	// wait for reload to happen (session should be invalidated)
	require.Eventually(t, func() bool {
		_, ok := srv.auth.GetSessionUser(sessionToken)
		return !ok // session invalidated
	}, 2*time.Second, 10*time.Millisecond, "session should be invalidated after reload")

	// new user should work
	newSessionToken, err := srv.auth.CreateSession("newuser")
	require.NoError(t, err)
	assert.NotEmpty(t, newSessionToken)

	// old user should not work
	user := srv.auth.ValidateUser("admin", "testpass")
	assert.Nil(t, user, "old user should not exist after reload")

	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shutdown in time")
	}
}

func TestServer_AuthHotReload_Disabled(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := tmpDir + "/auth.yml"
	// bcrypt hash for "testpass"
	authConfig := `users:
  - name: "admin"
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
`
	require.NoError(t, os.WriteFile(authFile, []byte(authConfig), 0o600))

	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv, err := New(st, validator.NewService(), nil, Config{
		Address: ":0", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile, AuthHotReload: false,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// run server in background
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()

	// give server time to start
	time.Sleep(100 * time.Millisecond)

	// create session
	sessionToken, err := srv.auth.CreateSession("admin")
	require.NoError(t, err)

	// update auth file
	newAuthConfig := `users:
  - name: "newuser"
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
`
	require.NoError(t, os.WriteFile(authFile, []byte(newAuthConfig), 0o600))

	// wait a bit
	time.Sleep(300 * time.Millisecond)

	// session should still be valid (no reload happened)
	user, ok := srv.auth.GetSessionUser(sessionToken)
	require.True(t, ok)
	assert.Equal(t, "admin", user)

	// old user should still work (config not reloaded)
	validatedUser := srv.auth.ValidateUser("admin", "testpass")
	assert.NotNil(t, validatedUser, "old user should still exist when hot-reload disabled")

	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not shutdown in time")
	}
}

func TestServer_AuthHotReload_PermissionChange(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := tmpDir + "/auth.yml"
	// bcrypt hash for "testpass"
	authConfig := `users:
  - name: "admin"
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
`
	require.NoError(t, os.WriteFile(authFile, []byte(authConfig), 0o600))

	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv, err := New(st, validator.NewService(), nil, Config{
		Address: ":0", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile, AuthHotReload: true,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// verify user has rw permission initially
	ok := srv.auth.CheckUserPermission("admin", "foo/bar", true) // write
	assert.True(t, ok, "admin should have write permission initially")

	// update permissions to read-only
	newAuthConfig := `users:
  - name: "admin"
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: r
`
	require.NoError(t, os.WriteFile(authFile, []byte(newAuthConfig), 0o600))

	// wait for reload
	require.Eventually(t, func() bool {
		return !srv.auth.CheckUserPermission("admin", "foo/bar", true) // should NOT have write
	}, 2*time.Second, 10*time.Millisecond, "permission should be updated after reload")

	// verify read permission still works
	assert.True(t, srv.auth.CheckUserPermission("admin", "foo/bar", false), "admin should have read permission")

	cancel()
	<-errCh
}

func TestServer_AuthHotReload_TokenChange(t *testing.T) {
	tmpDir := t.TempDir()
	authFile := tmpDir + "/auth.yml"
	authConfig := `tokens:
  - token: "oldtoken"
    permissions:
      - prefix: "*"
        access: rw
`
	require.NoError(t, os.WriteFile(authFile, []byte(authConfig), 0o600))

	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv, err := New(st, validator.NewService(), nil, Config{
		Address: ":0", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile, AuthHotReload: true,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Run(ctx) }()
	time.Sleep(100 * time.Millisecond)

	// verify old token works
	acl, ok := srv.auth.GetTokenACL("oldtoken")
	require.True(t, ok, "oldtoken should exist initially")
	assert.True(t, acl.CheckKeyPermission("foo/bar", true), "oldtoken should have write permission")

	// update to use new token
	newAuthConfig := `tokens:
  - token: "newtoken"
    permissions:
      - prefix: "app/*"
        access: r
`
	require.NoError(t, os.WriteFile(authFile, []byte(newAuthConfig), 0o600))

	// wait for reload - old token should disappear
	require.Eventually(t, func() bool {
		_, exists := srv.auth.GetTokenACL("oldtoken")
		return !exists
	}, 2*time.Second, 10*time.Millisecond, "old token should be removed after reload")

	// verify new token works
	newACL, newOk := srv.auth.GetTokenACL("newtoken")
	require.True(t, newOk, "newtoken should exist after reload")
	assert.True(t, newACL.CheckKeyPermission("app/config", false), "newtoken should have read permission for app/*")
	assert.False(t, newACL.CheckKeyPermission("app/config", true), "newtoken should NOT have write permission")
	assert.False(t, newACL.CheckKeyPermission("db/host", false), "newtoken should NOT have access to db/*")

	cancel()
	<-errCh
}

func TestServer_HandleList(t *testing.T) {
	now := time.Now()
	testKeys := []store.KeyInfo{
		{Key: "app/config", Size: 100, Format: "json", CreatedAt: now, UpdatedAt: now},
		{Key: "app/secret", Size: 50, Format: "text", CreatedAt: now, UpdatedAt: now},
		{Key: "db/host", Size: 20, Format: "text", CreatedAt: now, UpdatedAt: now},
	}

	t.Run("list all keys without auth", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) { return testKeys, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"Key":"app/config"`)
		assert.Contains(t, rec.Body.String(), `"Key":"app/secret"`)
		assert.Contains(t, rec.Body.String(), `"Key":"db/host"`)
	})

	t.Run("list keys with prefix filter", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) { return testKeys, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodGet, "/kv/?prefix=app/", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"Key":"app/config"`)
		assert.Contains(t, rec.Body.String(), `"Key":"app/secret"`)
		assert.NotContains(t, rec.Body.String(), `"Key":"db/host"`)
	})

	t.Run("list empty keys", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) { return []store.KeyInfo{}, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "[]\n", rec.Body.String())
	})

	t.Run("list returns internal error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) { return nil, errors.New("db error") },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestServer_HandleList_WithAuth(t *testing.T) {
	now := time.Now()
	testKeys := []store.KeyInfo{
		{Key: "app/config", Size: 100, Format: "json", CreatedAt: now, UpdatedAt: now},
		{Key: "app/secret", Size: 50, Format: "text", CreatedAt: now, UpdatedAt: now},
		{Key: "db/host", Size: 20, Format: "text", CreatedAt: now, UpdatedAt: now},
	}

	t.Run("list with token auth filters by permission", func(t *testing.T) {
		tmpDir := t.TempDir()
		authFile := tmpDir + "/auth.yml"
		authConfig := `tokens:
  - token: "apptoken"
    permissions:
      - prefix: "app/*"
        access: r
`
		require.NoError(t, os.WriteFile(authFile, []byte(authConfig), 0o600))

		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) { return testKeys, nil },
		}
		srv, err := New(st, validator.NewService(), nil, Config{
			Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile,
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.Header.Set("Authorization", "Bearer apptoken")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"Key":"app/config"`)
		assert.Contains(t, rec.Body.String(), `"Key":"app/secret"`)
		assert.NotContains(t, rec.Body.String(), `"Key":"db/host"`) // no permission
	})

	t.Run("list with invalid token returns 401", func(t *testing.T) {
		tmpDir := t.TempDir()
		authFile := tmpDir + "/auth.yml"
		authConfig := `tokens:
  - token: "validtoken"
    permissions:
      - prefix: "*"
        access: r
`
		require.NoError(t, os.WriteFile(authFile, []byte(authConfig), 0o600))

		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) { return testKeys, nil },
		}
		srv, err := New(st, validator.NewService(), nil, Config{
			Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile,
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.Header.Set("Authorization", "Bearer invalidtoken")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("list with session auth filters by user permission", func(t *testing.T) {
		tmpDir := t.TempDir()
		authFile := tmpDir + "/auth.yml"
		// bcrypt hash for "password123"
		authConfig := `users:
  - name: "dbadmin"
    password: "$2a$10$C615A0mfUEFBupj9qcqhiuBEyf60EqrsakB90CozUoSON8d2Dc1uS"
    permissions:
      - prefix: "db/*"
        access: rw
`
		require.NoError(t, os.WriteFile(authFile, []byte(authConfig), 0o600))

		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) { return testKeys, nil },
		}
		srv, err := New(st, validator.NewService(), nil, Config{
			Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile,
		})
		require.NoError(t, err)

		// create session for user
		sessionToken, err := srv.auth.CreateSession("dbadmin")
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: sessionToken})
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.NotContains(t, rec.Body.String(), `"Key":"app/config"`) // no permission
		assert.NotContains(t, rec.Body.String(), `"Key":"app/secret"`) // no permission
		assert.Contains(t, rec.Body.String(), `"Key":"db/host"`)       // has permission
	})

	t.Run("list with public access returns filtered keys", func(t *testing.T) {
		tmpDir := t.TempDir()
		authFile := tmpDir + "/auth.yml"
		authConfig := `tokens:
  - token: "*"
    permissions:
      - prefix: "app/*"
        access: r
`
		require.NoError(t, os.WriteFile(authFile, []byte(authConfig), 0o600))

		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) { return testKeys, nil },
		}
		srv, err := New(st, validator.NewService(), nil, Config{
			Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile,
		})
		require.NoError(t, err)

		// no auth header - should use public access
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"Key":"app/config"`)
		assert.Contains(t, rec.Body.String(), `"Key":"app/secret"`)
		assert.NotContains(t, rec.Body.String(), `"Key":"db/host"`) // no public permission
	})

	t.Run("admin token sees all keys even with public ACL configured", func(t *testing.T) {
		tmpDir := t.TempDir()
		authFile := tmpDir + "/auth.yml"
		// both public (limited) and admin (full) tokens configured
		authConfig := `tokens:
  - token: "*"
    permissions:
      - prefix: "app/*"
        access: r
  - token: "admintoken"
    permissions:
      - prefix: "*"
        access: rw
`
		require.NoError(t, os.WriteFile(authFile, []byte(authConfig), 0o600))

		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) { return testKeys, nil },
		}
		srv, err := New(st, validator.NewService(), nil, Config{
			Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile,
		})
		require.NoError(t, err)

		// admin token should see ALL keys, not just public subset
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.Header.Set("Authorization", "Bearer admintoken")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"Key":"app/config"`)
		assert.Contains(t, rec.Body.String(), `"Key":"app/secret"`)
		assert.Contains(t, rec.Body.String(), `"Key":"db/host"`) // admin sees everything
	})
}
