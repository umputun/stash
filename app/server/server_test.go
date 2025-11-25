package server

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/server/mocks"
	"github.com/umputun/stash/app/store"
)

func TestServer_HandleGet(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetFunc: func(key string) ([]byte, error) {
			switch key {
			case "testkey":
				return []byte("testvalue"), nil
			case "path/to/key":
				return []byte("nested value"), nil
			default:
				return nil, store.ErrNotFound
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
		GetFunc:  func(key string) ([]byte, error) { return nil, errors.New("db error") },
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	req := httptest.NewRequest(http.MethodGet, "/kv/testkey", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Len(t, st.GetCalls(), 1)
	assert.Equal(t, "testkey", st.GetCalls()[0].Key)
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
	_, err := New(st, Config{
		Address:     ":8080",
		ReadTimeout: 5 * time.Second,
		AuthFile:    "/nonexistent/auth.yml", // file doesn't exist
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize auth")
}

func TestServer_Handler_BaseURL(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetFunc: func(key string) ([]byte, error) {
			if key == "testkey" {
				return []byte("testvalue"), nil
			}
			return nil, store.ErrNotFound
		},
		SetFunc:  func(key string, value []byte, format string) error { return nil },
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}

	t.Run("without base URL routes work at root", func(t *testing.T) {
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", BaseURL: ""})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/kv/testkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "testvalue", rec.Body.String())
	})

	t.Run("with base URL routes work under prefix", func(t *testing.T) {
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", BaseURL: "/stash"})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/stash/kv/testkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "testvalue", rec.Body.String())
	})

	t.Run("base URL redirects to trailing slash", func(t *testing.T) {
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", BaseURL: "/stash"})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/stash", http.NoBody)
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusMovedPermanently, rec.Code)
		assert.Equal(t, "/stash/", rec.Header().Get("Location"))
	})

	t.Run("with base URL root path still accessible via prefix", func(t *testing.T) {
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", BaseURL: "/stash"})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/stash/ping", http.NoBody)
		rec := httptest.NewRecorder()
		srv.handler().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "pong", rec.Body.String())
	})

	t.Run("with base URL set correctly passes to KV API", func(t *testing.T) {
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", BaseURL: "/app/stash"})
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
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test"})
	require.NoError(t, err)
	return srv
}

func TestServer_WebHandlers_GitIntegration(t *testing.T) {
	t.Run("handleKeyCreate calls gitCommit", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return nil },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		gs := &mocks.GitStoreMock{
			CommitFunc: func(key string, value []byte, operation string, author git.Author) error { return nil },
		}
		srv := newTestServer(t, st)
		srv.SetGitStore(gs)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Form = map[string][]string{"key": {"testkey"}, "value": {"testvalue"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		require.Len(t, gs.CommitCalls(), 1, "gitCommit should be called")
		assert.Equal(t, "testkey", gs.CommitCalls()[0].Key)
		assert.Equal(t, []byte("testvalue"), gs.CommitCalls()[0].Value)
	})

	t.Run("handleKeyUpdate calls gitCommit", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return nil },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		gs := &mocks.GitStoreMock{
			CommitFunc: func(key string, value []byte, operation string, author git.Author) error { return nil },
		}
		srv := newTestServer(t, st)
		srv.SetGitStore(gs)

		req := httptest.NewRequest(http.MethodPut, "/web/keys/app/config", http.NoBody)
		req.Form = map[string][]string{"value": {"newvalue"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		require.Len(t, gs.CommitCalls(), 1, "gitCommit should be called")
		assert.Equal(t, "app/config", gs.CommitCalls()[0].Key)
		assert.Equal(t, []byte("newvalue"), gs.CommitCalls()[0].Value)
	})

	t.Run("handleKeyDelete calls gitDelete", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		gs := &mocks.GitStoreMock{
			DeleteFunc: func(key string, author git.Author) error { return nil },
		}
		srv := newTestServer(t, st)
		srv.SetGitStore(gs)

		req := httptest.NewRequest(http.MethodDelete, "/web/keys/app/config", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		require.Len(t, gs.DeleteCalls(), 1, "gitDelete should be called")
		assert.Equal(t, "app/config", gs.DeleteCalls()[0].Key)
	})
}

func TestServer_GetAuthorFromRequest(t *testing.T) {
	t.Run("returns default author when auth is nil", func(t *testing.T) {
		st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
		srv := newTestServer(t, st) // no auth configured

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		author := srv.getAuthorFromRequest(req)

		assert.Equal(t, git.DefaultAuthor(), author)
	})

	t.Run("returns default author when no session cookie", func(t *testing.T) {
		tmpDir := t.TempDir()
		authFile := tmpDir + "/auth.yml"
		require.NoError(t, os.WriteFile(authFile, []byte("users:\n  - name: testuser\n    password: pass\n"), 0o600))

		st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		author := srv.getAuthorFromRequest(req)

		assert.Equal(t, git.DefaultAuthor(), author)
	})

	t.Run("returns user author when valid session exists", func(t *testing.T) {
		tmpDir := t.TempDir()
		authFile := tmpDir + "/auth.yml"
		require.NoError(t, os.WriteFile(authFile, []byte("users:\n  - name: testuser\n    password: pass\n"), 0o600))

		st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile})
		require.NoError(t, err)

		// create session
		sessionToken, err := srv.auth.CreateSession("testuser")
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: sessionToken})
		author := srv.getAuthorFromRequest(req)

		assert.Equal(t, "testuser", author.Name)
		assert.Equal(t, "testuser@stash", author.Email)
	})

	t.Run("returns default author for invalid session", func(t *testing.T) {
		tmpDir := t.TempDir()
		authFile := tmpDir + "/auth.yml"
		require.NoError(t, os.WriteFile(authFile, []byte("users:\n  - name: testuser\n    password: pass\n"), 0o600))

		st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test", AuthFile: authFile})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "invalid-token"})
		author := srv.getAuthorFromRequest(req)

		assert.Equal(t, git.DefaultAuthor(), author)
	})
}
