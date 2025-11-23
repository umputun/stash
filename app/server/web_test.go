package server

import (
	"net/http"
	"net/http/httptest"
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
