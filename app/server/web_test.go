package server

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/mocks"
	"github.com/umputun/stash/app/store"
	"github.com/umputun/stash/app/validator"
)

func TestGetSortMode(t *testing.T) {
	tests := []struct {
		name     string
		cookie   string
		expected string
	}{
		{name: "no cookie returns default", cookie: "", expected: "updated"},
		{name: "updated cookie", cookie: "updated", expected: "updated"},
		{name: "key cookie", cookie: "key", expected: "key"},
		{name: "size cookie", cookie: "size", expected: "size"},
		{name: "created cookie", cookie: "created", expected: "created"},
		{name: "invalid cookie returns default", cookie: "invalid", expected: "updated"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "sort_mode", Value: tc.cookie})
			}
			result := getSortMode(req)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSortModeLabel(t *testing.T) {
	tests := []struct {
		mode     string
		expected string
	}{
		{mode: "updated", expected: "Updated"},
		{mode: "key", expected: "Key"},
		{mode: "size", expected: "Size"},
		{mode: "created", expected: "Created"},
		{mode: "invalid", expected: "Updated"},
	}

	for _, tc := range tests {
		t.Run(tc.mode, func(t *testing.T) {
			result := sortModeLabel(tc.mode)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestSortByMode(t *testing.T) {
	now := time.Now()
	keyInfoAccessor := func(k *store.KeyInfo) store.KeyInfo { return *k }

	t.Run("sort by updated descending", func(t *testing.T) {
		keys := []store.KeyInfo{
			{Key: "b", UpdatedAt: now.Add(-2 * time.Hour)},
			{Key: "a", UpdatedAt: now},
			{Key: "c", UpdatedAt: now.Add(-1 * time.Hour)},
		}
		sortByMode(keys, "updated", keyInfoAccessor)
		assert.Equal(t, "a", keys[0].Key)
		assert.Equal(t, "c", keys[1].Key)
		assert.Equal(t, "b", keys[2].Key)
	})

	t.Run("sort by key ascending", func(t *testing.T) {
		keys := []store.KeyInfo{
			{Key: "Zulu"},
			{Key: "alpha"},
			{Key: "Beta"},
		}
		sortByMode(keys, "key", keyInfoAccessor)
		assert.Equal(t, "alpha", keys[0].Key)
		assert.Equal(t, "Beta", keys[1].Key)
		assert.Equal(t, "Zulu", keys[2].Key)
	})

	t.Run("sort by size descending", func(t *testing.T) {
		keys := []store.KeyInfo{
			{Key: "small", Size: 10},
			{Key: "large", Size: 1000},
			{Key: "medium", Size: 100},
		}
		sortByMode(keys, "size", keyInfoAccessor)
		assert.Equal(t, "large", keys[0].Key)
		assert.Equal(t, "medium", keys[1].Key)
		assert.Equal(t, "small", keys[2].Key)
	})

	t.Run("sort by created descending", func(t *testing.T) {
		keys := []store.KeyInfo{
			{Key: "old", CreatedAt: now.Add(-2 * time.Hour)},
			{Key: "new", CreatedAt: now},
			{Key: "mid", CreatedAt: now.Add(-1 * time.Hour)},
		}
		sortByMode(keys, "created", keyInfoAccessor)
		assert.Equal(t, "new", keys[0].Key)
		assert.Equal(t, "mid", keys[1].Key)
		assert.Equal(t, "old", keys[2].Key)
	})
}

func TestHandleSortToggle(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return []store.KeyInfo{}, nil },
	}
	srv := newTestServer(t, st)

	tests := []struct {
		name        string
		currentMode string
		expectedNew string
	}{
		{name: "updated cycles to key", currentMode: "updated", expectedNew: "key"},
		{name: "key cycles to size", currentMode: "key", expectedNew: "size"},
		{name: "size cycles to created", currentMode: "size", expectedNew: "created"},
		{name: "created cycles to updated", currentMode: "created", expectedNew: "updated"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/web/sort", http.NoBody)
			req.AddCookie(&http.Cookie{Name: "sort_mode", Value: tc.currentMode})
			rec := httptest.NewRecorder()
			srv.routes().ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			cookies := rec.Result().Cookies()
			var sortCookie *http.Cookie
			for _, c := range cookies {
				if c.Name == "sort_mode" {
					sortCookie = c
					break
				}
			}
			require.NotNil(t, sortCookie, "sort_mode cookie should be set")
			assert.Equal(t, tc.expectedNew, sortCookie.Value)
		})
	}
}

func TestValueForDisplay(t *testing.T) {
	t.Run("utf8 passthrough", func(t *testing.T) {
		value, isBinary := valueForDisplay([]byte("hello world"))
		assert.Equal(t, "hello world", value)
		assert.False(t, isBinary)
	})

	t.Run("binary base64 encoding", func(t *testing.T) {
		binary := []byte{0x00, 0xFF, 0x80}
		value, isBinary := valueForDisplay(binary)
		assert.Equal(t, "AP+A", value)
		assert.True(t, isBinary)
	})
}

func TestValueFromForm(t *testing.T) {
	t.Run("text decoding", func(t *testing.T) {
		value, err := valueFromForm("hello", false)
		require.NoError(t, err)
		assert.Equal(t, []byte("hello"), value)
	})

	t.Run("binary base64 decoding", func(t *testing.T) {
		value, err := valueFromForm("AP+A", true)
		require.NoError(t, err)
		assert.Equal(t, []byte{0x00, 0xFF, 0x80}, value)
	})

	t.Run("invalid base64 returns error", func(t *testing.T) {
		_, err := valueFromForm("not-valid-base64!!!", true)
		assert.Error(t, err)
	})
}

func TestFilterBySearch(t *testing.T) {
	keys := []store.KeyInfo{
		{Key: "config/db"},
		{Key: "config/app"},
		{Key: "secrets/api"},
	}
	keyAccessor := func(k store.KeyInfo) string { return k.Key }

	t.Run("empty search returns all", func(t *testing.T) {
		result := filterBySearch(keys, "", keyAccessor)
		assert.Len(t, result, 3)
	})

	t.Run("filters by substring", func(t *testing.T) {
		result := filterBySearch(keys, "config", keyAccessor)
		assert.Len(t, result, 2)
	})

	t.Run("case insensitive", func(t *testing.T) {
		result := filterBySearch(keys, "CONFIG", keyAccessor)
		assert.Len(t, result, 2)
	})

	t.Run("no matches returns empty", func(t *testing.T) {
		result := filterBySearch(keys, "notfound", keyAccessor)
		assert.Empty(t, result)
	})
}

func TestHandleIndex(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) {
			return []store.KeyInfo{{Key: "test", Size: 100}}, nil
		},
	}
	srv := newTestServer(t, st)

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Stash")
	assert.Contains(t, rec.Body.String(), "test")
}

func TestHandleKeyList(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) {
			return []store.KeyInfo{
				{Key: "alpha", Size: 50},
				{Key: "beta", Size: 100},
			}, nil
		},
	}
	srv := newTestServer(t, st)

	t.Run("returns key list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "alpha")
		assert.Contains(t, rec.Body.String(), "beta")
	})

	t.Run("filters with search", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys?search=alpha", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "alpha")
		assert.NotContains(t, rec.Body.String(), ">beta<")
	})
}

func TestHandleKeyNew(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	req := httptest.NewRequest(http.MethodGet, "/web/keys/new", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Create Key")
}

func TestHandleKeyView(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			if key == "testkey" {
				return []byte("testvalue"), "text", nil
			}
			return nil, "", store.ErrNotFound
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	t.Run("existing key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/testkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "testvalue")
	})

	t.Run("not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/missing", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestHandleKeyEdit(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			if key == "editkey" {
				return []byte("editvalue"), "text", nil
			}
			return nil, "", store.ErrNotFound
		},
		GetInfoFunc: func(key string) (store.KeyInfo, error) {
			return store.KeyInfo{Key: key, UpdatedAt: time.Now()}, nil
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	t.Run("existing key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/editkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "editvalue")
	})

	t.Run("not found", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/missing", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestHandleKeyCreate(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) { return nil, "", store.ErrNotFound },
		SetFunc:           func(key string, value []byte, format string) error { return nil },
		ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = map[string][]string{
		"key":   {"newkey"},
		"value": {"newvalue"},
	}
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, st.SetCalls(), 1)
	assert.Equal(t, "newkey", st.SetCalls()[0].Key)
	assert.Equal(t, "newvalue", string(st.SetCalls()[0].Value))
}

func TestHandleKeyUpdate(t *testing.T) {
	st := &mocks.KVStoreMock{
		SetFunc:  func(key string, value []byte, format string) error { return nil },
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	req := httptest.NewRequest(http.MethodPut, "/web/keys/updatekey", http.NoBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = map[string][]string{
		"value": {"updated"},
	}
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.Len(t, st.SetCalls(), 1)
	assert.Equal(t, "updatekey", st.SetCalls()[0].Key)
	assert.Equal(t, "updated", string(st.SetCalls()[0].Value))
}

func TestHandleKeyDelete(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodDelete, "/web/keys/deletekey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.DeleteCalls(), 1)
		assert.Equal(t, "deletekey", st.DeleteCalls()[0].Key)
	})

	t.Run("not found", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return store.ErrNotFound },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodDelete, "/web/keys/missing", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("internal error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return errors.New("db error") },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodDelete, "/web/keys/errorkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestHandleKeyCreate_Errors(t *testing.T) {
	t.Run("empty key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return nil },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {""}, "value": {"val"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Empty(t, st.SetCalls())
	})

	t.Run("store error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(key string) ([]byte, string, error) { return nil, "", store.ErrNotFound },
			SetFunc:           func(key string, value []byte, format string) error { return errors.New("db error") },
			ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"testkey"}, "value": {"val"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})

	t.Run("duplicate key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			GetWithFormatFunc: func(key string) ([]byte, string, error) { return []byte("existing"), "text", nil },
			SetFunc:           func(key string, value []byte, format string) error { return nil },
			ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"existing-key"}, "value": {"val"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code) // form re-rendered with error
		body := rec.Body.String()
		assert.Contains(t, body, "already exists")
		assert.Empty(t, st.SetCalls(), "Set should not be called for duplicate key")
		// verify save button is visible and no force button (can't force duplicate)
		assert.Contains(t, body, `id="save-btn"`)
		assert.NotContains(t, body, `id="force-btn"`)
	})
}

func TestHandleKeyUpdate_Errors(t *testing.T) {
	t.Run("store error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte, format string) error { return errors.New("db error") },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"updated"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestHandleKeyCreate_Validation(t *testing.T) {
	tests := []struct {
		name       string
		format     string
		value      string
		force      string
		wantSet    bool // whether Set should be called
		wantStatus int
	}{
		{name: "valid json saves", format: "json", value: `{"key":"value"}`, force: "", wantSet: true, wantStatus: http.StatusOK},
		{name: "invalid json returns error", format: "json", value: `{bad json}`, force: "", wantSet: false, wantStatus: http.StatusOK},
		{name: "invalid json with force saves", format: "json", value: `{bad json}`, force: "true", wantSet: true, wantStatus: http.StatusOK},
		{name: "valid yaml saves", format: "yaml", value: "key: value", force: "", wantSet: true, wantStatus: http.StatusOK},
		{name: "invalid yaml returns error", format: "yaml", value: "key:\n\tbad", force: "", wantSet: false, wantStatus: http.StatusOK},
		{name: "invalid yaml with force saves", format: "yaml", value: "key:\n\tbad", force: "true", wantSet: true, wantStatus: http.StatusOK},
		{name: "text bypasses validation", format: "text", value: `{not valid json but who cares}`, force: "", wantSet: true, wantStatus: http.StatusOK},
		{name: "shell bypasses validation", format: "shell", value: `echo $VAR`, force: "", wantSet: true, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &mocks.KVStoreMock{
				GetWithFormatFunc: func(key string) ([]byte, string, error) { return nil, "", store.ErrNotFound },
				SetFunc:           func(key string, value []byte, format string) error { return nil },
				ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
			}
			srv := newTestServer(t, st)

			form := map[string][]string{
				"key":    {"testkey"},
				"value":  {tt.value},
				"format": {tt.format},
			}
			if tt.force != "" {
				form["force"] = []string{tt.force}
			}

			req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.PostForm = form
			rec := httptest.NewRecorder()
			srv.routes().ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantSet {
				require.Len(t, st.SetCalls(), 1, "expected Set to be called")
				assert.Equal(t, "testkey", st.SetCalls()[0].Key)
			} else {
				assert.Empty(t, st.SetCalls(), "expected Set NOT to be called")
				// verify error message is in response (form re-rendered with error)
				body := rec.Body.String()
				assert.Contains(t, body, "invalid")
				// verify save button is hidden and force button is shown
				assert.Contains(t, body, `id="save-btn"`)
				assert.Contains(t, body, `style="display:none"`)
				assert.Contains(t, body, `id="force-btn"`)
			}
		})
	}
}

func TestHandleKeyUpdate_Validation(t *testing.T) {
	tests := []struct {
		name       string
		format     string
		value      string
		force      string
		wantSet    bool
		wantStatus int
	}{
		{name: "valid json saves", format: "json", value: `["item1","item2"]`, force: "", wantSet: true, wantStatus: http.StatusOK},
		{name: "invalid json returns error", format: "json", value: `[missing bracket`, force: "", wantSet: false, wantStatus: http.StatusOK},
		{name: "invalid json with force saves", format: "json", value: `[missing bracket`, force: "true", wantSet: true, wantStatus: http.StatusOK},
		{name: "valid toml saves", format: "toml", value: `key = "value"`, force: "", wantSet: true, wantStatus: http.StatusOK},
		{name: "invalid toml returns error", format: "toml", value: `key "no equals"`, force: "", wantSet: false, wantStatus: http.StatusOK},
		{name: "invalid toml with force saves", format: "toml", value: `key "no equals"`, force: "true", wantSet: true, wantStatus: http.StatusOK},
		{name: "text bypasses validation", format: "text", value: `anything goes here`, force: "", wantSet: true, wantStatus: http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &mocks.KVStoreMock{
				SetFunc: func(key string, value []byte, format string) error { return nil },
				GetInfoFunc: func(key string) (store.KeyInfo, error) {
					return store.KeyInfo{Key: key, UpdatedAt: time.Now()}, nil
				},
				ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
			}
			srv := newTestServer(t, st)

			form := map[string][]string{
				"value":  {tt.value},
				"format": {tt.format},
			}
			if tt.force != "" {
				form["force"] = []string{tt.force}
			}

			req := httptest.NewRequest(http.MethodPut, "/web/keys/updatekey", http.NoBody)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.PostForm = form
			rec := httptest.NewRecorder()
			srv.routes().ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Code)
			if tt.wantSet {
				require.Len(t, st.SetCalls(), 1, "expected Set to be called")
				assert.Equal(t, "updatekey", st.SetCalls()[0].Key)
			} else {
				assert.Empty(t, st.SetCalls(), "expected Set NOT to be called")
				body := rec.Body.String()
				assert.Contains(t, body, "invalid")
				// verify save button is hidden and force button is shown
				assert.Contains(t, body, `id="save-btn"`)
				assert.Contains(t, body, `style="display:none"`)
				assert.Contains(t, body, `id="force-btn"`)
			}
		})
	}
}

func TestHandleKeyUpdate_ConflictDetection(t *testing.T) {
	originalTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	modifiedTime := time.Date(2024, 1, 1, 12, 5, 0, 0, time.UTC) // 5 minutes later

	t.Run("conflict detected when timestamp differs", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{Key: key, UpdatedAt: modifiedTime}, nil // server has newer timestamp
			},
			GetWithFormatFunc: func(key string) ([]byte, string, error) {
				return []byte("server value"), "text", nil
			},
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		form := url.Values{
			"value":      {"my edited value"},
			"format":     {"text"},
			"updated_at": {fmt.Sprintf("%d", originalTime.Unix())}, // old timestamp
		}

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, st.SetCalls(), "expected Set NOT to be called on conflict")
		body := rec.Body.String()
		assert.Contains(t, body, "Conflict detected")
		assert.Contains(t, body, "server value")
		assert.Contains(t, body, "Reload")
		assert.Contains(t, body, "Overwrite")
	})

	t.Run("no conflict when timestamps match", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{Key: key, UpdatedAt: originalTime}, nil
			},
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		form := url.Values{
			"value":      {"my edited value"},
			"format":     {"text"},
			"updated_at": {fmt.Sprintf("%d", originalTime.Unix())},
		}

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1, "expected Set to be called")
	})

	t.Run("force_overwrite bypasses conflict check", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{Key: key, UpdatedAt: modifiedTime}, nil // server has newer timestamp
			},
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		form := url.Values{
			"value":           {"my edited value"},
			"format":          {"text"},
			"updated_at":      {fmt.Sprintf("%d", originalTime.Unix())}, // old timestamp
			"force_overwrite": {"true"},
		}

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1, "expected Set to be called when force_overwrite=true")
	})

	t.Run("no updated_at skips conflict check", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc: func(key string, value []byte, format string) error { return nil },
			GetInfoFunc: func(key string) (store.KeyInfo, error) {
				return store.KeyInfo{Key: key, UpdatedAt: modifiedTime}, nil
			},
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		form := url.Values{
			"value":  {"my edited value"},
			"format": {"text"},
			// no updated_at field
		}

		req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, st.SetCalls(), 1, "expected Set to be called without updated_at")
	})
}

func TestHandleKeyUpdate_ValidationPreservesTimestamp(t *testing.T) {
	// this test verifies that when validation fails, the form re-renders with
	// the ORIGINAL timestamp from the request, not a fresh one from the store.
	// this prevents a race condition where another user's changes could be
	// silently overwritten after a validation retry.
	originalTime := time.Date(2024, 1, 1, 12, 0, 0, 0, time.UTC)
	serverTime := time.Date(2024, 1, 1, 12, 10, 0, 0, time.UTC) // server has newer timestamp

	st := &mocks.KVStoreMock{
		SetFunc: func(key string, value []byte, format string) error { return nil },
		GetInfoFunc: func(key string) (store.KeyInfo, error) {
			// return ORIGINAL time first (for conflict check), then server time (simulating race)
			return store.KeyInfo{Key: key, UpdatedAt: originalTime}, nil
		},
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			return []byte("test value"), "text", nil
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	val := &mocks.ValidatorMock{
		ValidateFunc: func(format string, value []byte) error {
			return fmt.Errorf("invalid JSON") // force validation to fail
		},
	}
	srv := newTestServerWithValidator(t, st, val)

	form := url.Values{
		"value":      {"{invalid json"},
		"format":     {"json"},
		"updated_at": {fmt.Sprintf("%d", originalTime.Unix())}, // user's original timestamp
	}

	req := httptest.NewRequest(http.MethodPut, "/web/keys/testkey", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, st.SetCalls(), "expected Set NOT to be called on validation error")

	body := rec.Body.String()
	// the form should preserve the ORIGINAL timestamp, not the server's newer one
	assert.Contains(t, body, fmt.Sprintf(`value="%d"`, originalTime.Unix()),
		"form should preserve original timestamp for conflict detection on retry")
	assert.NotContains(t, body, fmt.Sprintf(`value="%d"`, serverTime.Unix()),
		"form should NOT use server's newer timestamp")
}

func TestHandleThemeToggle(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	tests := []struct {
		name     string
		current  string
		expected string
	}{
		{"no theme to dark", "", "dark"},
		{"light to dark", "light", "dark"},
		{"dark to light", "dark", "light"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/web/theme", http.NoBody)
			if tc.current != "" {
				req.AddCookie(&http.Cookie{Name: "theme", Value: tc.current})
			}
			rec := httptest.NewRecorder()
			srv.routes().ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			var themeCookie *http.Cookie
			for _, c := range rec.Result().Cookies() {
				if c.Name == "theme" {
					themeCookie = c
					break
				}
			}
			require.NotNil(t, themeCookie)
			assert.Equal(t, tc.expected, themeCookie.Value)
		})
	}
}

func TestHandleViewModeToggle(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	srv := newTestServer(t, st)

	tests := []struct {
		name     string
		current  string
		expected string
	}{
		{"no mode to cards", "", "cards"},
		{"grid to cards", "grid", "cards"},
		{"cards to grid", "cards", "grid"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/web/view-mode", http.NoBody)
			if tc.current != "" {
				req.AddCookie(&http.Cookie{Name: "view_mode", Value: tc.current})
			}
			rec := httptest.NewRecorder()
			srv.routes().ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			var viewCookie *http.Cookie
			for _, c := range rec.Result().Cookies() {
				if c.Name == "view_mode" {
					viewCookie = c
					break
				}
			}
			require.NotNil(t, viewCookie)
			assert.Equal(t, tc.expected, viewCookie.Value)
		})
	}
}

func TestGetTheme(t *testing.T) {
	tests := []struct {
		name     string
		cookie   string
		expected string
	}{
		{"no cookie", "", ""},
		{"light", "light", "light"},
		{"dark", "dark", "dark"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "theme", Value: tc.cookie})
			}
			assert.Equal(t, tc.expected, getTheme(req))
		})
	}
}

func TestGetViewMode(t *testing.T) {
	tests := []struct {
		name     string
		cookie   string
		expected string
	}{
		{"no cookie returns grid", "", "grid"},
		{"grid", "grid", "grid"},
		{"cards", "cards", "cards"},
		{"invalid returns grid", "invalid", "grid"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "view_mode", Value: tc.cookie})
			}
			assert.Equal(t, tc.expected, getViewMode(req))
		})
	}
}

func TestHandleLoginForm(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createTestAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/login", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Login")
	assert.Contains(t, rec.Body.String(), "Username")
	assert.Contains(t, rec.Body.String(), "Password")
}

func TestHandleLogin(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createTestAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("valid credentials redirects", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"username": {"admin"}, "password": {"testpass"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusSeeOther, rec.Code)
		assert.Equal(t, "/", rec.Header().Get("Location"))
		// should have auth cookie
		var authCookie *http.Cookie
		for _, c := range rec.Result().Cookies() {
			if c.Name == "stash-auth" || c.Name == "__Host-stash-auth" {
				authCookie = c
				break
			}
		}
		require.NotNil(t, authCookie)
	})

	t.Run("invalid credentials shows error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"username": {"admin"}, "password": {"wrongpass"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "Invalid username or password")
	})
}

func TestHandleLogout(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createTestAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/logout", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "somesession"})
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login", rec.Header().Get("Location"))
	// should clear cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "stash-auth" {
			assert.Equal(t, -1, c.MaxAge)
		}
	}
}

func TestServer_URL(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}

	tests := []struct {
		name    string
		baseURL string
		path    string
		want    string
	}{
		{name: "empty base URL", baseURL: "", path: "/web/keys", want: "/web/keys"},
		{name: "with base URL", baseURL: "/stash", path: "/web/keys", want: "/stash/web/keys"},
		{name: "nested base URL", baseURL: "/app/stash", path: "/kv/test", want: "/app/stash/kv/test"},
		{name: "root path", baseURL: "/stash", path: "/", want: "/stash/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, BaseURL: tc.baseURL})
			require.NoError(t, err)
			assert.Equal(t, tc.want, srv.url(tc.path))
		})
	}
}

func TestServer_CookiePath(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}

	tests := []struct {
		name    string
		baseURL string
		want    string
	}{
		{name: "empty base URL", baseURL: "", want: "/"},
		{name: "with base URL", baseURL: "/stash", want: "/stash/"},
		{name: "nested base URL", baseURL: "/app/stash", want: "/app/stash/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, BaseURL: tc.baseURL})
			require.NoError(t, err)
			assert.Equal(t, tc.want, srv.cookiePath())
		})
	}
}

func TestHandleKeyView_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			switch key {
			case "app/config", "other/key":
				return []byte("value"), "text", nil
			}
			return nil, "", store.ErrNotFound
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin can view any key", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("readonly user can view any key", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user can view key in allowed prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/app/config", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user cannot view key outside allowed prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/view/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestHandleKeyEdit_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) {
			switch key {
			case "app/config", "other/key":
				return []byte("value"), "text", nil
			}
			return nil, "", store.ErrNotFound
		},
		GetInfoFunc: func(key string) (store.KeyInfo, error) {
			return store.KeyInfo{Key: key, UpdatedAt: time.Now()}, nil
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin can edit any key", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("readonly user cannot edit", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("scoped user can edit key in allowed prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/app/config", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user cannot edit key outside prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/edit/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestHandleKeyCreate_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetWithFormatFunc: func(key string) ([]byte, string, error) { return nil, "", store.ErrNotFound },
		SetFunc:           func(key string, value []byte, format string) error { return nil },
		ListFunc:          func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin can create any key", func(t *testing.T) {
		st.SetCalls() // reset
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"other/newkey"}, "value": {"val"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("readonly user cannot create", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"other/newkey"}, "value": {"val"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code) // returns form with error message
		assert.Contains(t, rec.Body.String(), "Access denied")
	})

	t.Run("scoped user can create key in allowed prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"app/newkey"}, "value": {"val"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user cannot create key outside prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"other/newkey"}, "value": {"val"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code) // returns form with error message
		assert.Contains(t, rec.Body.String(), "Access denied")
	})
}

func TestHandleKeyUpdate_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		SetFunc:  func(key string, value []byte, format string) error { return nil },
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin can update any key", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodPut, "/web/keys/other/key", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"updated"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("readonly user cannot update", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodPut, "/web/keys/other/key", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"updated"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code) // returns form with error message
		assert.Contains(t, rec.Body.String(), "Access denied")
	})

	t.Run("scoped user can update key in allowed prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodPut, "/web/keys/app/config", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"updated"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user cannot update key outside prefix", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodPut, "/web/keys/other/key", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"value": {"updated"}}
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code) // returns form with error message
		assert.Contains(t, rec.Body.String(), "Access denied")
	})
}

func TestHandleKeyDelete_PermissionEnforcement(t *testing.T) {
	authFile := createMultiUserAuthFile(t)

	t.Run("admin can delete any key", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
		require.NoError(t, err)

		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodDelete, "/web/keys/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("readonly user cannot delete", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
		require.NoError(t, err)

		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodDelete, "/web/keys/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("scoped user can delete key in allowed prefix", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
		require.NoError(t, err)

		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodDelete, "/web/keys/app/config", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("scoped user cannot delete key outside prefix", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			DeleteFunc: func(key string) error { return nil },
			ListFunc:   func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
		require.NoError(t, err)

		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodDelete, "/web/keys/other/key", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})
}

func TestHandleKeyList_PermissionFiltering(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) {
			return []store.KeyInfo{
				{Key: "app/config", Size: 50},
				{Key: "app/db", Size: 100},
				{Key: "other/secret", Size: 200},
			}, nil
		},
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin sees all keys", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "app/config")
		assert.Contains(t, rec.Body.String(), "app/db")
		assert.Contains(t, rec.Body.String(), "other/secret")
	})

	t.Run("readonly user sees all keys", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "app/config")
		assert.Contains(t, rec.Body.String(), "other/secret")
	})

	t.Run("scoped user sees only allowed keys", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "app/config")
		assert.Contains(t, rec.Body.String(), "app/db")
		assert.NotContains(t, rec.Body.String(), "other/secret")
	})
}

func TestHandleKeyList_MixedPermissions(t *testing.T) {
	// test that user with mixed permissions (rw on some prefixes, r on others)
	// sees Edit/Delete buttons only for keys they can write to
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) {
			return []store.KeyInfo{
				{Key: "app/config", Size: 50},
				{Key: "app/database", Size: 100},
				{Key: "secrets/password", Size: 20},
				{Key: "secrets/aws-key", Size: 30},
			}, nil
		},
	}
	authFile := createMixedPermAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	cookie := loginAndGetCookie(t, srv, "mixed")
	req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()

	// user sees all keys they have access to
	assert.Contains(t, body, "app/config")
	assert.Contains(t, body, "app/database")
	assert.Contains(t, body, "secrets/password")
	assert.Contains(t, body, "secrets/aws-key")

	// action column header should be present (user has write access to some keys)
	assert.Contains(t, body, `class="actions-cell"`)

	// check that Edit buttons appear for app/* keys (rw access)
	assert.Contains(t, body, `/web/keys/edit/app%2Fconfig`)
	assert.Contains(t, body, `/web/keys/edit/app%2Fdatabase`)

	// check that Edit buttons do NOT appear for secrets/* keys (r only access)
	assert.NotContains(t, body, `/web/keys/edit/secrets%2Fpassword`)
	assert.NotContains(t, body, `/web/keys/edit/secrets%2Faws-key`)
}

func TestHandleKeyNew_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("admin can access new key form", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/new", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "Create Key")
	})

	t.Run("readonly user cannot access new key form", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "readonly")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/new", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("scoped user can access new key form", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "scoped")
		req := httptest.NewRequest(http.MethodGet, "/web/keys/new", http.NoBody)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestGetCurrentUser(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("returns username from stash-auth cookie", func(t *testing.T) {
		cookie := loginAndGetCookie(t, srv, "admin")
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.AddCookie(cookie)
		username := srv.getCurrentUser(req)
		assert.Equal(t, "admin", username)
	})

	t.Run("returns empty for no cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		username := srv.getCurrentUser(req)
		assert.Empty(t, username)
	})

	t.Run("returns empty for invalid session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "invalid-session"})
		username := srv.getCurrentUser(req)
		assert.Empty(t, username)
	})
}

func TestCalculateModalDimensions(t *testing.T) {
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second})
	require.NoError(t, err)

	tests := []struct {
		name          string
		value         string
		wantWidth     int
		wantHeight    int
		wantWidthMin  int
		wantWidthMax  int
		wantHeightMin int
		wantHeightMax int
	}{
		{name: "empty value", value: "", wantWidth: 600, wantHeight: 104},
		{name: "short value", value: "hello", wantWidth: 600, wantHeight: 104},
		{name: "medium line 60 chars", value: "123456789012345678901234567890123456789012345678901234567890",
			wantWidth: 600, wantHeight: 104},
		{name: "long line hits max width", value: string(make([]byte, 200)),
			wantWidth: 1200, wantHeight: 104},
		{name: "few lines uses min lines", value: "line1\nline2", wantWidth: 600, wantHeight: 104},
		{name: "10 lines", value: "1\n2\n3\n4\n5\n6\n7\n8\n9\n10",
			wantWidth: 600, wantHeight: 224},
		{name: "many lines hits max height", value: "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20",
			wantWidth: 600, wantHeight: 384},
		{name: "cyrillic uses rune count not bytes", value: "привет мир",
			wantWidth: 600, wantHeight: 104},
		{name: "japanese uses rune count not bytes", value: "こんにちは世界",
			wantWidthMin: 600, wantWidthMax: 700, wantHeightMin: 104, wantHeightMax: 104},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			width, height := srv.calculateModalDimensions(tc.value)
			if tc.wantWidthMin > 0 {
				assert.GreaterOrEqual(t, width, tc.wantWidthMin, "width should be >= min")
				assert.LessOrEqual(t, width, tc.wantWidthMax, "width should be <= max")
			} else {
				assert.Equal(t, tc.wantWidth, width, "width mismatch")
			}
			if tc.wantHeightMin > 0 {
				assert.GreaterOrEqual(t, height, tc.wantHeightMin, "height should be >= min")
				assert.LessOrEqual(t, height, tc.wantHeightMax, "height should be <= max")
			} else {
				assert.Equal(t, tc.wantHeight, height, "height mismatch")
			}
		})
	}
}

// createTestAuthFile creates a temporary auth.yml file with admin user for testing.
// admin user has password "testpass" with full access.
func createTestAuthFile(t *testing.T) string {
	t.Helper()
	// bcrypt hash for "testpass"
	content := `users:
  - name: admin
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
`
	dir := t.TempDir()
	f := filepath.Join(dir, "auth.yml")
	err := os.WriteFile(f, []byte(content), 0o600)
	require.NoError(t, err)
	return f
}

func TestLoginThrottle(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createTestAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	// use httptest.Server for true concurrent requests
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	// login throttle is set to 5 concurrent requests
	// send 15 concurrent requests to ensure some get throttled
	// use valid credentials so bcrypt runs and keeps requests in flight longer
	const numRequests = 15
	var wg sync.WaitGroup
	var throttledCount atomic.Int32
	var successCount atomic.Int32
	var otherCount atomic.Int32

	// use a channel to synchronize start
	start := make(chan struct{})

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // wait for signal to start

			// send valid credentials so bcrypt runs (~50ms) keeping requests in flight
			resp, err := http.PostForm(ts.URL+"/login", map[string][]string{
				"username": {"admin"},
				"password": {"testpass"},
			})
			if err != nil {
				return
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK, http.StatusBadRequest, http.StatusSeeOther, http.StatusUnauthorized:
				// these are valid responses (login succeeded/failed/redirected)
				successCount.Add(1)
			case http.StatusServiceUnavailable: // throttled
				throttledCount.Add(1)
			default:
				otherCount.Add(1)
				t.Logf("unexpected status: %d", resp.StatusCode)
			}
		}()
	}

	// start all goroutines simultaneously
	close(start)
	wg.Wait()

	// with 15 concurrent requests and limit of 5, some should be throttled
	t.Logf("success: %d, throttled: %d, other: %d", successCount.Load(), throttledCount.Load(), otherCount.Load())
	assert.Positive(t, throttledCount.Load(), "some requests should be throttled")
	assert.Equal(t, int32(numRequests), successCount.Load()+throttledCount.Load()+otherCount.Load(), "all requests should complete")
}

// createMultiUserAuthFile creates auth file with multiple users for permission testing.
// - admin: full rw access to all keys
// - readonly: read-only access to all keys
// - scoped: rw access to app/* prefix only
func createMultiUserAuthFile(t *testing.T) string {
	t.Helper()
	// bcrypt hash for "testpass"
	content := `users:
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
`
	dir := t.TempDir()
	f := filepath.Join(dir, "auth.yml")
	err := os.WriteFile(f, []byte(content), 0o600)
	require.NoError(t, err)
	return f
}

func createMixedPermAuthFile(t *testing.T) string {
	t.Helper()
	// bcrypt hash for "testpass"
	content := `users:
  - name: mixed
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "app/*"
        access: rw
      - prefix: "secrets/*"
        access: r
`
	dir := t.TempDir()
	f := filepath.Join(dir, "auth.yml")
	err := os.WriteFile(f, []byte(content), 0o600)
	require.NoError(t, err)
	return f
}

// loginAndGetCookie logs in a user and returns the session cookie for subsequent requests.
func loginAndGetCookie(t *testing.T, srv *Server, username string) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.PostForm = map[string][]string{"username": {username}, "password": {"testpass"}}
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)
	require.Equal(t, http.StatusSeeOther, rec.Code, "login should succeed for user %s", username)
	for _, c := range rec.Result().Cookies() {
		if c.Name == "stash-auth" || c.Name == "__Host-stash-auth" {
			return c
		}
	}
	t.Fatalf("no auth cookie found after login for user %s", username)
	return nil
}

func TestFilterKeysByPermission(t *testing.T) {
	authFile := createMultiUserAuthFile(t)
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	keys := []store.KeyInfo{
		{Key: "app/config", Size: 50},
		{Key: "app/db", Size: 100},
		{Key: "other/secret", Size: 200},
	}

	t.Run("admin sees all keys with write permission", func(t *testing.T) {
		result := srv.filterKeysByPermission("admin", keys)
		assert.Len(t, result, 3)
		for _, k := range result {
			assert.True(t, k.CanWrite, "admin should have write permission for %s", k.Key)
		}
	})

	t.Run("readonly sees all keys without write permission", func(t *testing.T) {
		result := srv.filterKeysByPermission("readonly", keys)
		assert.Len(t, result, 3)
		for _, k := range result {
			assert.False(t, k.CanWrite, "readonly should not have write permission for %s", k.Key)
		}
	})

	t.Run("scoped sees only allowed prefix with write permission", func(t *testing.T) {
		result := srv.filterKeysByPermission("scoped", keys)
		assert.Len(t, result, 2)
		for _, k := range result {
			assert.True(t, k.CanWrite, "scoped should have write permission for %s", k.Key)
			assert.Contains(t, k.Key, "app/")
		}
	})

	t.Run("unknown user sees nothing", func(t *testing.T) {
		result := srv.filterKeysByPermission("unknown", keys)
		assert.Empty(t, result)
	})
}
