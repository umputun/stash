package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/web/mocks"
	"github.com/umputun/stash/app/store"
)

func TestHandler_HandleKeyList(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func(context.Context) ([]store.KeyInfo, error) {
			return []store.KeyInfo{
				{Key: "alpha", Size: 50},
				{Key: "beta", Size: 100},
			}, nil
		},
	}
	h := newTestHandlerWithStore(t, st)

	t.Run("returns key list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
		rec := httptest.NewRecorder()
		h.handleKeyList(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "alpha")
		assert.Contains(t, rec.Body.String(), "beta")
	})

	t.Run("filters with search query param", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys?search=alpha", http.NoBody)
		rec := httptest.NewRecorder()
		h.handleKeyList(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		assert.Contains(t, body, "alpha")
		assert.NotContains(t, body, ">beta<")
	})
}

func TestHandler_HandleKeyNew(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/web/keys/new", http.NoBody)
	rec := httptest.NewRecorder()
	h.handleKeyNew(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Create Key")
}

func TestHandler_HandleKeyNew_PermissionDenied(t *testing.T) {
	auth := &mocks.AuthProviderMock{
		UserCanWriteFunc: func(username string) bool { return false },
	}
	h := newTestHandlerWithAuth(t, auth)

	req := httptest.NewRequest(http.MethodGet, "/web/keys/new", http.NoBody)
	rec := httptest.NewRecorder()
	h.handleKeyNew(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandler_HandleKeyView(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(_ context.Context, key string) ([]byte, string, error) {
			if key == "testkey" {
				return []byte("testvalue"), "text", nil
			}
			return nil, "", store.ErrNotFound
		},
		ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
	}
	auth := &mocks.AuthProviderMock{
		CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
	}
	h := newTestHandlerWithStoreAndAuth(t, st, auth)

	t.Run("existing key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/testkey", http.NoBody)
		req.SetPathValue("key", "testkey")
		rec := httptest.NewRecorder()
		h.handleKeyView(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "testvalue")
	})

	t.Run("not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/missing", http.NoBody)
		req.SetPathValue("key", "missing")
		rec := httptest.NewRecorder()
		h.handleKeyView(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestHandler_HandleKeyView_PermissionDenied(t *testing.T) {
	auth := &mocks.AuthProviderMock{
		CheckUserPermissionFunc: func(username, key string, write bool) bool { return false },
	}
	h := newTestHandlerWithAuth(t, auth)

	req := httptest.NewRequest(http.MethodGet, "/web/keys/view/testkey", http.NoBody)
	req.SetPathValue("key", "testkey")
	rec := httptest.NewRecorder()
	h.handleKeyView(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandler_HandleKeyEdit(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(_ context.Context, key string) ([]byte, string, error) {
			if key == "editkey" {
				return []byte("editvalue"), "text", nil
			}
			return nil, "", store.ErrNotFound
		},
		GetInfoFunc: func(_ context.Context, key string) (store.KeyInfo, error) {
			return store.KeyInfo{Key: key, UpdatedAt: time.Now()}, nil
		},
		ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
	}
	auth := &mocks.AuthProviderMock{
		CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
	}
	h := newTestHandlerWithStoreAndAuth(t, st, auth)

	t.Run("existing key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/editkey", http.NoBody)
		req.SetPathValue("key", "editkey")
		rec := httptest.NewRecorder()
		h.handleKeyEdit(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "editvalue")
	})

	t.Run("not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/missing", http.NoBody)
		req.SetPathValue("key", "missing")
		rec := httptest.NewRecorder()
		h.handleKeyEdit(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("permission denied", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(context.Context, string) ([]byte, string, error) { return []byte("val"), "text", nil },
			ListFunc:          func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return false },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/restricted", http.NoBody)
		req.SetPathValue("key", "restricted")
		rec := httptest.NewRecorder()
		h.handleKeyEdit(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("store error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(context.Context, string) ([]byte, string, error) { return nil, "", errors.New("db error") },
			ListFunc:          func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/error-key", http.NoBody)
		req.SetPathValue("key", "error-key")
		rec := httptest.NewRecorder()
		h.handleKeyEdit(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestHandler_HandleKeyCreate(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(context.Context, string) ([]byte, string, error) { return nil, "", store.ErrNotFound },
		SetFunc:           func(context.Context, string, []byte, string) error { return nil },
		ListFunc:          func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
	}
	auth := &mocks.AuthProviderMock{
		CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		FilterUserKeysFunc:      func(username string, keys []string) []string { return keys },
		UserCanWriteFunc:        func(username string) bool { return true },
	}
	h := newTestHandlerWithAll(t, st, defaultValidatorMock(), auth)

	req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = map[string][]string{
		"key":   {"newkey"},
		"value": {"newvalue"},
	}
	rec := httptest.NewRecorder()
	h.handleKeyCreate(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, st.SetCalls(), 1)
	assert.Equal(t, "newkey", st.SetCalls()[0].Key)
	assert.Equal(t, "newvalue", string(st.SetCalls()[0].Value))
}

func TestHandler_HandleKeyCreate_Errors(t *testing.T) {
	t.Run("empty key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(context.Context, string, []byte, string) error { return nil },
			ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		h := newTestHandlerWithStore(t, st)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {""}, "value": {"val"}}
		rec := httptest.NewRecorder()
		h.handleKeyCreate(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Empty(t, st.SetCalls())
	})

	t.Run("store error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(context.Context, string) ([]byte, string, error) { return nil, "", store.ErrNotFound },
			SetFunc:           func(context.Context, string, []byte, string) error { return errors.New("db error") },
			ListFunc:          func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		}
		h := newTestHandlerWithAll(t, st, defaultValidatorMock(), auth)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"testkey"}, "value": {"val"}}
		rec := httptest.NewRecorder()
		h.handleKeyCreate(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("duplicate key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(context.Context, string) ([]byte, string, error) { return []byte("existing"), "text", nil },
			SetFunc:           func(context.Context, string, []byte, string) error { return nil },
			ListFunc:          func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"existing-key"}, "value": {"val"}}
		rec := httptest.NewRecorder()
		h.handleKeyCreate(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code) // form re-rendered with error
		body := rec.Body.String()
		assert.Contains(t, body, "already exists")
		assert.Empty(t, st.SetCalls(), "Set should not be called for duplicate key")
	})

	t.Run("permission denied", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(context.Context, string) ([]byte, string, error) { return nil, "", store.ErrNotFound },
			ListFunc:          func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return false },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"restricted/key"}, "value": {"val"}}
		rec := httptest.NewRecorder()
		h.handleKeyCreate(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		assert.Contains(t, body, "Access denied")
	})

	t.Run("store check error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(context.Context, string) ([]byte, string, error) {
				return nil, "", errors.New("db connection failed")
			},
			ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"newkey"}, "value": {"val"}}
		rec := httptest.NewRecorder()
		h.handleKeyCreate(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestHandler_HandleKeyUpdate(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetWithVersionFunc: func(context.Context, string, []byte, string, time.Time) error { return nil },
			ListFunc:           func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
			FilterUserKeysFunc:      func(username string, keys []string) []string { return keys },
			UserCanWriteFunc:        func(username string) bool { return true },
		}
		h := newTestHandlerWithAll(t, st, defaultValidatorMock(), auth)

		req := httptest.NewRequest(http.MethodPut, "/web/keys/updatekey", http.NoBody)
		req.SetPathValue("key", "updatekey")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"updated"}}
		rec := httptest.NewRecorder()
		h.handleKeyUpdate(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetWithVersionCalls(), 1)
		assert.Equal(t, "updatekey", st.SetWithVersionCalls()[0].Key)
		assert.Equal(t, "updated", string(st.SetWithVersionCalls()[0].Value))
	})

	t.Run("permission denied", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return false },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodPut, "/web/keys/restricted", http.NoBody)
		req.SetPathValue("key", "restricted")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"val"}}
		rec := httptest.NewRecorder()
		h.handleKeyUpdate(rec, req)

		// handler re-renders form with error message (HTMX pattern)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "Access denied")
	})

	t.Run("store error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetWithVersionFunc: func(context.Context, string, []byte, string, time.Time) error {
				return errors.New("db error")
			},
			ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", http.NoBody)
		req.SetPathValue("key", "testkey")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"val"}}
		rec := httptest.NewRecorder()
		h.handleKeyUpdate(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("validation error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		}
		val := &mocks.ValidatorMock{
			IsValidFormatFunc:    func(format string) bool { return true },
			ValidateFunc:         func(format string, value []byte) error { return errors.New("invalid json") },
			SupportedFormatsFunc: func() []string { return []string{"text", "json", "yaml"} },
		}
		h := newTestHandlerWithAll(t, st, val, auth)

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", http.NoBody)
		req.SetPathValue("key", "testkey")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {`{invalid`}, "format": {"json"}}
		rec := httptest.NewRecorder()
		h.handleKeyUpdate(rec, req)

		// handler re-renders form with validation error (HTMX pattern)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "invalid json")
	})
}

func TestHandler_HandleKeyDelete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(context.Context, string) error { return nil },
			ListFunc:   func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
			FilterUserKeysFunc:      func(username string, keys []string) []string { return keys },
			UserCanWriteFunc:        func(username string) bool { return true },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodDelete, "/web/keys/deletekey", http.NoBody)
		req.SetPathValue("key", "deletekey")
		rec := httptest.NewRecorder()
		h.handleKeyDelete(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.DeleteCalls(), 1)
		assert.Equal(t, "deletekey", st.DeleteCalls()[0].Key)
	})

	t.Run("not found", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(context.Context, string) error { return store.ErrNotFound },
			ListFunc:   func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodDelete, "/web/keys/missing", http.NoBody)
		req.SetPathValue("key", "missing")
		rec := httptest.NewRecorder()
		h.handleKeyDelete(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("internal error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(context.Context, string) error { return errors.New("db error") },
			ListFunc:   func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodDelete, "/web/keys/errorkey", http.NoBody)
		req.SetPathValue("key", "errorkey")
		rec := httptest.NewRecorder()
		h.handleKeyDelete(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("permission denied", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(context.Context, string) error { return nil },
			ListFunc:   func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return false },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodDelete, "/web/keys/nowrite", http.NoBody)
		req.SetPathValue("key", "nowrite")
		rec := httptest.NewRecorder()
		h.handleKeyDelete(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestHandler_HandleKeyUpdate_ConflictDetection(t *testing.T) {
	originalTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	modifiedTime := time.Date(2024, 1, 1, 12, 5, 0, 0, time.UTC) // 5 minutes later

	t.Run("conflict detected when version mismatch", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetWithVersionFunc: func(_ context.Context, _ string, _ []byte, _ string, expectedVersion time.Time) error {
				// return ConflictError with server's current state
				return &store.ConflictError{
					Info: store.ConflictInfo{
						CurrentValue:     []byte("server value"),
						CurrentFormat:    "text",
						CurrentVersion:   modifiedTime,
						AttemptedVersion: expectedVersion,
					},
				}
			},
			ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		}
		h := newTestHandlerWithStoreAndAuth(t, st, auth)

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", http.NoBody)
		req.SetPathValue("key", "testkey")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{
			"value":      {"my edited value"},
			"format":     {"text"},
			"updated_at": {strconv.FormatInt(originalTime.Unix(), 10)}, // old timestamp
		}
		rec := httptest.NewRecorder()
		h.handleKeyUpdate(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetWithVersionCalls(), 1, "expected SetWithVersion to be called")
		body := rec.Body.String()
		assert.Contains(t, body, "Conflict detected")
		assert.Contains(t, body, "server value")
	})

	t.Run("force_overwrite bypasses conflict check", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetWithVersionFunc: func(context.Context, string, []byte, string, time.Time) error {
				return nil // success
			},
			ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		}
		auth := &mocks.AuthProviderMock{
			CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
			FilterUserKeysFunc:      func(username string, keys []string) []string { return keys },
			UserCanWriteFunc:        func(username string) bool { return true },
		}
		h := newTestHandlerWithAll(t, st, defaultValidatorMock(), auth)

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", http.NoBody)
		req.SetPathValue("key", "testkey")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{
			"value":           {"my edited value"},
			"format":          {"text"},
			"updated_at":      {strconv.FormatInt(originalTime.Unix(), 10)},
			"force_overwrite": {"true"},
		}
		rec := httptest.NewRecorder()
		h.handleKeyUpdate(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetWithVersionCalls(), 1, "expected SetWithVersion to be called")
		// verify zero time was passed (no version check)
		assert.True(t, st.SetWithVersionCalls()[0].ExpectedVersion.IsZero(), "expected zero time for force_overwrite")
	})
}

func TestHandler_RenderValidationError(t *testing.T) {
	h := newTestHandler(t)

	t.Run("renders form with error message", func(t *testing.T) {
		rec := httptest.NewRecorder()
		params := validationErrorParams{
			Key:       "test/key",
			Value:     `{"invalid": json`,
			Format:    "json",
			IsBinary:  false,
			Username:  "testuser",
			Error:     "invalid json: unexpected end of JSON input",
			UpdatedAt: 1234567890,
		}
		h.renderValidationError(rec, params)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "#modal-content", rec.Header().Get("HX-Retarget"))
		assert.Equal(t, "innerHTML", rec.Header().Get("HX-Reswap"))
		body := rec.Body.String()
		assert.Contains(t, body, "test/key")
		assert.Contains(t, body, "invalid json")
		assert.Contains(t, body, "1234567890")
	})

	t.Run("sets CanForce to true", func(t *testing.T) {
		rec := httptest.NewRecorder()
		params := validationErrorParams{
			Key:    "key",
			Value:  "value",
			Format: "yaml",
			Error:  "validation error",
		}
		h.renderValidationError(rec, params)

		body := rec.Body.String()
		// form should contain force submit button since CanForce is true
		assert.Contains(t, body, "Submit Anyway")
		assert.Contains(t, body, `name="force"`)
	})
}

// newTestHandlerWithStoreAndAuth creates a test handler with custom store and auth.
func newTestHandlerWithStoreAndAuth(t *testing.T, st KVStore, auth AuthProvider) *Handler {
	t.Helper()
	h, err := New(st, auth, defaultValidatorMock(), nil, Config{})
	require.NoError(t, err)
	return h
}

// newTestHandlerWithAll creates a test handler with all custom dependencies.
func newTestHandlerWithAll(t *testing.T, st KVStore, val Validator, auth AuthProvider) *Handler {
	t.Helper()
	h, err := New(st, auth, val, nil, Config{})
	require.NoError(t, err)
	return h
}
