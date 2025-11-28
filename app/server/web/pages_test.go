package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/web/mocks"
	"github.com/umputun/stash/app/store"
)

func TestHandler_HandleIndex(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) {
			return []store.KeyInfo{{Key: "test", Size: 100}}, nil
		},
	}
	h := newTestHandlerWithStore(t, st)

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	h.handleIndex(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Stash")
	assert.Contains(t, rec.Body.String(), "test")
}

func TestHandler_HandleIndex_StoreError(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) {
			return nil, assert.AnError
		},
	}
	h := newTestHandlerWithStore(t, st)

	req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()
	h.handleIndex(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestHandler_HandleIndex_WithPagination(t *testing.T) {
	keys := make([]store.KeyInfo, 10)
	for i := range keys {
		keys[i] = store.KeyInfo{Key: "key" + string(rune('a'+i)), Size: 100}
	}
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return keys, nil },
	}
	auth := &mocks.AuthProviderMock{
		EnabledFunc:             func() bool { return false },
		FilterUserKeysFunc:      func(username string, keys []string) []string { return keys },
		CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		UserCanWriteFunc:        func(username string) bool { return true },
	}
	h, err := New(st, auth, defaultValidatorMock(), nil, Config{PageSize: 3})
	require.NoError(t, err)

	t.Run("first page", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		rec := httptest.NewRecorder()
		h.handleIndex(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		assert.Contains(t, body, "10 keys") // total count
		assert.Contains(t, body, "1 / 4")   // page indicator
	})

	t.Run("page 2 via query param", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?page=2", http.NoBody)
		rec := httptest.NewRecorder()
		h.handleIndex(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		assert.Contains(t, body, "2 / 4") // page indicator
	})
}

func TestHandler_HandleThemeToggle(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	h := newTestHandlerWithStore(t, st)

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
			h.handleThemeToggle(rec, req)

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

func TestHandler_HandleViewModeToggle(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	h := newTestHandlerWithStore(t, st)

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
			h.handleViewModeToggle(rec, req)

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

func TestHandler_HandleSortToggle(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return []store.KeyInfo{}, nil },
	}
	h := newTestHandlerWithStore(t, st)

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
			h.handleSortToggle(rec, req)

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
