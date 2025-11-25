package server

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/mocks"
	"github.com/umputun/stash/app/store"
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

func TestSortKeys(t *testing.T) {
	now := time.Now()

	t.Run("sort by updated descending", func(t *testing.T) {
		keys := []store.KeyInfo{
			{Key: "b", UpdatedAt: now.Add(-2 * time.Hour)},
			{Key: "a", UpdatedAt: now},
			{Key: "c", UpdatedAt: now.Add(-1 * time.Hour)},
		}
		sortKeys(keys, "updated")
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
		sortKeys(keys, "key")
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
		sortKeys(keys, "size")
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
		sortKeys(keys, "created")
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

func TestFilterKeys(t *testing.T) {
	keys := []store.KeyInfo{
		{Key: "config/db"},
		{Key: "config/app"},
		{Key: "secrets/api"},
	}

	t.Run("empty search returns all", func(t *testing.T) {
		result := filterKeys(keys, "")
		assert.Len(t, result, 3)
	})

	t.Run("filters by substring", func(t *testing.T) {
		result := filterKeys(keys, "config")
		assert.Len(t, result, 2)
	})

	t.Run("case insensitive", func(t *testing.T) {
		result := filterKeys(keys, "CONFIG")
		assert.Len(t, result, 2)
	})

	t.Run("no matches returns empty", func(t *testing.T) {
		result := filterKeys(keys, "notfound")
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
		GetFunc: func(key string) ([]byte, error) {
			if key == "testkey" {
				return []byte("testvalue"), nil
			}
			return nil, store.ErrNotFound
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
		GetFunc: func(key string) ([]byte, error) {
			if key == "editkey" {
				return []byte("editvalue"), nil
			}
			return nil, store.ErrNotFound
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
		SetFunc:  func(key string, value []byte) error { return nil },
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
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
		SetFunc:  func(key string, value []byte) error { return nil },
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
			SetFunc:  func(key string, value []byte) error { return nil },
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
			SetFunc:  func(key string, value []byte) error { return errors.New("db error") },
			ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
		}
		srv := newTestServer(t, st)

		req := httptest.NewRequest(http.MethodPost, "/web/keys", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"key": {"testkey"}, "value": {"val"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

func TestHandleKeyUpdate_Errors(t *testing.T) {
	t.Run("store error", func(t *testing.T) {
		st := &mocks.KVStoreMock{
			SetFunc:  func(key string, value []byte) error { return errors.New("db error") },
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
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
			srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, BaseURL: tc.baseURL})
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
			srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, BaseURL: tc.baseURL})
			require.NoError(t, err)
			assert.Equal(t, tc.want, srv.cookiePath())
		})
	}
}

func TestHandleKeyView_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		GetFunc: func(key string) ([]byte, error) {
			switch key {
			case "app/config", "other/key":
				return []byte("value"), nil
			}
			return nil, store.ErrNotFound
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
		GetFunc: func(key string) ([]byte, error) {
			switch key {
			case "app/config", "other/key":
				return []byte("value"), nil
			}
			return nil, store.ErrNotFound
		},
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
		SetFunc:  func(key string, value []byte) error { return nil },
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
		SetFunc:  func(key string, value []byte) error { return nil },
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
		srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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

func TestHandleKeyNew_PermissionEnforcement(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createMultiUserAuthFile(t)
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second})
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
	srv, err := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
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
