package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/server/api/mocks"
	"github.com/umputun/stash/app/store"
)

func TestHandler_HandleList(t *testing.T) {
	t.Run("returns all keys", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) {
				return []store.KeyInfo{
					{Key: "alpha", Size: 50},
					{Key: "beta", Size: 100},
				}, nil
			},
		}
		auth := &mocks.AuthProviderMock{
			EnabledFunc: func() bool { return false },
		}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		rec := httptest.NewRecorder()
		h.handleList(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "alpha")
		assert.Contains(t, rec.Body.String(), "beta")
	})

	t.Run("filters by prefix", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) {
				return []store.KeyInfo{
					{Key: "app/config", Size: 50},
					{Key: "app/db", Size: 100},
					{Key: "other/key", Size: 30},
				}, nil
			},
		}
		auth := &mocks.AuthProviderMock{
			EnabledFunc: func() bool { return false },
		}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/?prefix=app/", http.NoBody)
		rec := httptest.NewRecorder()
		h.handleList(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		assert.Contains(t, body, "app/config")
		assert.Contains(t, body, "app/db")
		assert.NotContains(t, body, "other/key")
	})

	t.Run("store error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			ListFunc: func() ([]store.KeyInfo, error) {
				return nil, errors.New("db error")
			},
		}
		auth := &mocks.AuthProviderMock{}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		rec := httptest.NewRecorder()
		h.handleList(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestHandler_HandleGet(t *testing.T) {
	t.Run("existing key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(key string) ([]byte, string, error) {
				if key == "testkey" {
					return []byte("testvalue"), "text", nil
				}
				return nil, "", store.ErrNotFound
			},
		}
		auth := &mocks.AuthProviderMock{}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/testkey", http.NoBody)
		req.SetPathValue("key", "testkey")
		rec := httptest.NewRecorder()
		h.handleGet(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "testvalue", rec.Body.String())
		assert.Equal(t, "text/plain", rec.Header().Get("Content-Type"))
	})

	t.Run("json format returns application/json", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(key string) ([]byte, string, error) {
				return []byte(`{"key":"value"}`), "json", nil
			},
		}
		auth := &mocks.AuthProviderMock{}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/config", http.NoBody)
		req.SetPathValue("key", "config")
		rec := httptest.NewRecorder()
		h.handleGet(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	})

	t.Run("not found", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(key string) ([]byte, string, error) {
				return nil, "", store.ErrNotFound
			},
		}
		auth := &mocks.AuthProviderMock{}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/missing", http.NoBody)
		req.SetPathValue("key", "missing")
		rec := httptest.NewRecorder()
		h.handleGet(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("empty key", func(t *testing.T) {
		st := &mocks.KVStoreMock{}
		auth := &mocks.AuthProviderMock{}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.SetPathValue("key", "")
		rec := httptest.NewRecorder()
		h.handleGet(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestHandler_HandleSet(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
		}
		auth := &mocks.AuthProviderMock{}
		h := New(st, auth, defaultFormatValidator(), nil)

		req := httptest.NewRequest(http.MethodPut, "/kv/newkey", strings.NewReader("newvalue"))
		req.SetPathValue("key", "newkey")
		rec := httptest.NewRecorder()
		h.handleSet(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "newkey", st.SetCalls()[0].Key)
		assert.Equal(t, "newvalue", string(st.SetCalls()[0].Value))
		assert.Equal(t, "text", st.SetCalls()[0].Format) // default format
	})

	t.Run("with format header", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
		}
		auth := &mocks.AuthProviderMock{}
		h := New(st, auth, defaultFormatValidator(), nil)

		req := httptest.NewRequest(http.MethodPut, "/kv/config", strings.NewReader(`{"key":"value"}`))
		req.SetPathValue("key", "config")
		req.Header.Set("X-Stash-Format", "json")
		rec := httptest.NewRecorder()
		h.handleSet(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "json", st.SetCalls()[0].Format)
	})

	t.Run("with format query param", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
		}
		auth := &mocks.AuthProviderMock{}
		h := New(st, auth, defaultFormatValidator(), nil)

		req := httptest.NewRequest(http.MethodPut, "/kv/config?format=yaml", strings.NewReader("key: value"))
		req.SetPathValue("key", "config")
		rec := httptest.NewRecorder()
		h.handleSet(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "yaml", st.SetCalls()[0].Format)
	})

	t.Run("invalid format defaults to text", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
		}
		auth := &mocks.AuthProviderMock{}
		h := New(st, auth, defaultFormatValidator(), nil)

		req := httptest.NewRequest(http.MethodPut, "/kv/key", strings.NewReader("value"))
		req.SetPathValue("key", "key")
		req.Header.Set("X-Stash-Format", "invalid")
		rec := httptest.NewRecorder()
		h.handleSet(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1)
		assert.Equal(t, "text", st.SetCalls()[0].Format)
	})

	t.Run("empty key", func(t *testing.T) {
		st := &mocks.KVStoreMock{}
		auth := &mocks.AuthProviderMock{}
		h := New(st, auth, defaultFormatValidator(), nil)

		req := httptest.NewRequest(http.MethodPut, "/kv/", strings.NewReader("value"))
		req.SetPathValue("key", "")
		rec := httptest.NewRecorder()
		h.handleSet(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("store error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return errors.New("db error") },
		}
		auth := &mocks.AuthProviderMock{}
		h := New(st, auth, defaultFormatValidator(), nil)

		req := httptest.NewRequest(http.MethodPut, "/kv/key", strings.NewReader("value"))
		req.SetPathValue("key", "key")
		rec := httptest.NewRecorder()
		h.handleSet(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestHandler_HandleDelete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
		}
		auth := &mocks.AuthProviderMock{}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodDelete, "/kv/deletekey", http.NoBody)
		req.SetPathValue("key", "deletekey")
		rec := httptest.NewRecorder()
		h.handleDelete(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		require.Len(t, st.DeleteCalls(), 1)
		assert.Equal(t, "deletekey", st.DeleteCalls()[0].Key)
	})

	t.Run("not found", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return store.ErrNotFound },
		}
		auth := &mocks.AuthProviderMock{}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodDelete, "/kv/missing", http.NoBody)
		req.SetPathValue("key", "missing")
		rec := httptest.NewRecorder()
		h.handleDelete(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("store error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return errors.New("db error") },
		}
		auth := &mocks.AuthProviderMock{}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodDelete, "/kv/errorkey", http.NoBody)
		req.SetPathValue("key", "errorkey")
		rec := httptest.NewRecorder()
		h.handleDelete(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("empty key", func(t *testing.T) {
		st := &mocks.KVStoreMock{}
		auth := &mocks.AuthProviderMock{}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodDelete, "/kv/", http.NoBody)
		req.SetPathValue("key", "")
		rec := httptest.NewRecorder()
		h.handleDelete(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestHandler_FormatToContentType(t *testing.T) {
	st := &mocks.KVStoreMock{}
	auth := &mocks.AuthProviderMock{}
	h := newTestHandler(t, st, auth)

	tests := []struct {
		format   string
		expected string
	}{
		{format: "json", expected: "application/json"},
		{format: "yaml", expected: "application/yaml"},
		{format: "xml", expected: "application/xml"},
		{format: "toml", expected: "application/toml"},
		{format: "text", expected: "text/plain"},
		{format: "hcl", expected: "text/plain"},
		{format: "ini", expected: "text/plain"},
		{format: "shell", expected: "text/x-shellscript"},
		{format: "unknown", expected: "application/octet-stream"},
	}

	for _, tc := range tests {
		t.Run(tc.format, func(t *testing.T) {
			result := h.formatToContentType(tc.format)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestHandler_FilterKeysByAuth(t *testing.T) {
	keys := []string{"app/config", "app/db", "secret/key"}

	t.Run("no auth returns all keys", func(t *testing.T) {
		st := &mocks.KVStoreMock{}
		auth := &mocks.AuthProviderMock{
			EnabledFunc: func() bool { return false },
		}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		result := h.filterKeysByAuth(req, keys)
		assert.Equal(t, keys, result)
	})

	t.Run("session cookie filters keys", func(t *testing.T) {
		st := &mocks.KVStoreMock{}
		auth := &mocks.AuthProviderMock{
			EnabledFunc: func() bool { return true },
			GetSessionUserFunc: func(token string) (string, bool) {
				if token == "valid-token" {
					return "testuser", true
				}
				return "", false
			},
			FilterUserKeysFunc: func(username string, keys []string) []string {
				return []string{"app/config", "app/db"} // filter out secret/key
			},
		}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "valid-token"})
		result := h.filterKeysByAuth(req, keys)
		assert.Equal(t, []string{"app/config", "app/db"}, result)
	})

	t.Run("bearer token filters keys", func(t *testing.T) {
		st := &mocks.KVStoreMock{}
		auth := &mocks.AuthProviderMock{
			EnabledFunc:        func() bool { return true },
			GetSessionUserFunc: func(token string) (string, bool) { return "", false },
			FilterTokenKeysFunc: func(token string, keys []string) []string {
				if token == "api-token" {
					return []string{"app/config"}
				}
				return nil
			},
		}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.Header.Set("Authorization", "Bearer api-token")
		result := h.filterKeysByAuth(req, keys)
		assert.Equal(t, []string{"app/config"}, result)
	})

	t.Run("public access filters keys", func(t *testing.T) {
		st := &mocks.KVStoreMock{}
		auth := &mocks.AuthProviderMock{
			EnabledFunc:         func() bool { return true },
			GetSessionUserFunc:  func(token string) (string, bool) { return "", false },
			FilterTokenKeysFunc: func(token string, keys []string) []string { return nil },
			FilterPublicKeysFunc: func(keys []string) []string {
				return []string{"app/config"} // only public keys
			},
		}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		result := h.filterKeysByAuth(req, keys)
		assert.Equal(t, []string{"app/config"}, result)
	})

	t.Run("no valid auth returns nil", func(t *testing.T) {
		st := &mocks.KVStoreMock{}
		auth := &mocks.AuthProviderMock{
			EnabledFunc:          func() bool { return true },
			GetSessionUserFunc:   func(token string) (string, bool) { return "", false },
			FilterTokenKeysFunc:  func(token string, keys []string) []string { return nil },
			FilterPublicKeysFunc: func(keys []string) []string { return nil },
		}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		result := h.filterKeysByAuth(req, keys)
		assert.Nil(t, result)
	})
}

func TestHandler_GetIdentity(t *testing.T) {
	t.Run("no auth returns anonymous", func(t *testing.T) {
		h := &Handler{auth: nil}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		id := h.getIdentity(req)
		assert.Equal(t, identityAnonymous, id.typ)
	})

	t.Run("session cookie returns user identity", func(t *testing.T) {
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(token string) (string, bool) {
				if token == "valid" {
					return "testuser", true
				}
				return "", false
			},
		}
		h := &Handler{auth: auth}

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "valid"})
		id := h.getIdentity(req)
		assert.Equal(t, identityUser, id.typ)
		assert.Equal(t, "testuser", id.name)
	})

	t.Run("bearer token returns token identity", func(t *testing.T) {
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(token string) (string, bool) { return "", false },
			HasTokenACLFunc:    func(token string) bool { return token == "api-token" },
		}
		h := &Handler{auth: auth}

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("Authorization", "Bearer api-token")
		id := h.getIdentity(req)
		assert.Equal(t, identityToken, id.typ)
		assert.Equal(t, "token:api-toke", id.name) // truncated to 8 chars
	})
}

func TestHandler_GetIdentityForLog(t *testing.T) {
	t.Run("user identity", func(t *testing.T) {
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(token string) (string, bool) { return "admin", true },
		}
		h := &Handler{auth: auth}

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "token"})
		result := h.getIdentityForLog(req)
		assert.Equal(t, "user:admin", result)
	})

	t.Run("anonymous identity", func(t *testing.T) {
		h := &Handler{auth: nil}
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		result := h.getIdentityForLog(req)
		assert.Equal(t, "anonymous", result)
	})
}

func TestHandler_HandleSet_WithGit(t *testing.T) {
	st := &mocks.KVStoreMock{
		SetFunc: func(key string, value []byte, format string) error { return nil },
	}
	auth := &mocks.AuthProviderMock{}
	gitMock := &mocks.GitServiceMock{
		CommitFunc: func(req git.CommitRequest) error {
			assert.Equal(t, "testkey", req.Key)
			assert.Equal(t, "testvalue", string(req.Value))
			assert.Equal(t, "set", req.Operation)
			return nil
		},
	}
	h := New(st, auth, defaultFormatValidator(), gitMock)

	req := httptest.NewRequest(http.MethodPut, "/kv/testkey", strings.NewReader("testvalue"))
	req.SetPathValue("key", "testkey")
	rec := httptest.NewRecorder()
	h.handleSet(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, gitMock.CommitCalls(), 1, "git commit should be called")
}

func TestHandler_HandleDelete_WithGit(t *testing.T) {
	st := &mocks.KVStoreMock{
		DeleteFunc: func(key string) error { return nil },
	}
	auth := &mocks.AuthProviderMock{}
	gitMock := &mocks.GitServiceMock{
		DeleteFunc: func(key string, author git.Author) error {
			assert.Equal(t, "testkey", key)
			return nil
		},
	}
	h := New(st, auth, defaultFormatValidator(), gitMock)

	req := httptest.NewRequest(http.MethodDelete, "/kv/testkey", http.NoBody)
	req.SetPathValue("key", "testkey")
	rec := httptest.NewRecorder()
	h.handleDelete(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	require.Len(t, gitMock.DeleteCalls(), 1, "git delete should be called")
}

// defaultFormatValidator returns a format validator mock that accepts standard formats.
func defaultFormatValidator() FormatValidator {
	return &mocks.FormatValidatorMock{
		IsValidFormatFunc: func(format string) bool {
			valid := []string{"text", "json", "yaml", "xml", "toml", "ini", "hcl", "shell"}
			for _, f := range valid {
				if f == format {
					return true
				}
			}
			return false
		},
	}
}

// helper to create test handler with default format validator
func newTestHandler(t *testing.T, st KVStore, auth AuthProvider) *Handler {
	t.Helper()
	return New(st, auth, defaultFormatValidator(), nil)
}

func TestHandler_GetAuthorFromRequest(t *testing.T) {
	st := &mocks.KVStoreMock{}

	t.Run("user identity returns author with username", func(t *testing.T) {
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(token string) (string, bool) {
				if token == "valid-session" {
					return "testuser", true
				}
				return "", false
			},
			HasTokenACLFunc: func(token string) bool { return false },
		}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "valid-session"})

		author := h.getAuthorFromRequest(req)
		assert.Equal(t, "testuser", author.Name)
		assert.Equal(t, "testuser@stash", author.Email)
	})

	t.Run("token identity returns author with token prefix", func(t *testing.T) {
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(token string) (string, bool) { return "", false },
			HasTokenACLFunc:    func(token string) bool { return token == "my-api-token" },
		}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.Header.Set("Authorization", "Bearer my-api-token")

		author := h.getAuthorFromRequest(req)
		// token gets truncated to first 8 chars: "my-api-t"
		assert.Equal(t, "token:my-api-t", author.Name)
		assert.Equal(t, "token:my-api-t@stash", author.Email)
	})

	t.Run("anonymous returns default author", func(t *testing.T) {
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(token string) (string, bool) { return "", false },
			HasTokenACLFunc:    func(token string) bool { return false },
		}
		h := newTestHandler(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)

		author := h.getAuthorFromRequest(req)
		expected := git.DefaultAuthor()
		assert.Equal(t, expected.Name, author.Name)
		assert.Equal(t, expected.Email, author.Email)
	})
}
