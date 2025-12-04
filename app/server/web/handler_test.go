package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/server/web/mocks"
	"github.com/umputun/stash/app/store"
)

func TestSortModeLabel(t *testing.T) {
	tests := []struct {
		mode     enum.SortMode
		expected string
	}{
		{mode: enum.SortModeUpdated, expected: "Updated"},
		{mode: enum.SortModeKey, expected: "Key"},
		{mode: enum.SortModeSize, expected: "Size"},
		{mode: enum.SortModeCreated, expected: "Created"},
	}

	for _, tc := range tests {
		t.Run(tc.mode.String(), func(t *testing.T) {
			result := sortModeLabel(tc.mode)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestHandler_GetTheme(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name     string
		cookie   string
		expected enum.Theme
	}{
		{name: "no cookie", cookie: "", expected: enum.ThemeSystem},
		{name: "light theme", cookie: "light", expected: enum.ThemeLight},
		{name: "dark theme", cookie: "dark", expected: enum.ThemeDark},
		{name: "invalid theme", cookie: "invalid", expected: enum.ThemeSystem},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "theme", Value: tc.cookie})
			}
			result := h.getTheme(req)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestHandler_GetViewMode(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name     string
		cookie   string
		expected enum.ViewMode
	}{
		{name: "no cookie returns grid", cookie: "", expected: enum.ViewModeGrid},
		{name: "grid", cookie: "grid", expected: enum.ViewModeGrid},
		{name: "cards", cookie: "cards", expected: enum.ViewModeCards},
		{name: "invalid returns grid", cookie: "invalid", expected: enum.ViewModeGrid},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "view_mode", Value: tc.cookie})
			}
			result := h.getViewMode(req)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestHandler_GetSortMode(t *testing.T) {
	h := newTestHandler(t)

	tests := []struct {
		name     string
		cookie   string
		expected enum.SortMode
	}{
		{name: "no cookie returns default", cookie: "", expected: enum.SortModeUpdated},
		{name: "updated cookie", cookie: "updated", expected: enum.SortModeUpdated},
		{name: "key cookie", cookie: "key", expected: enum.SortModeKey},
		{name: "size cookie", cookie: "size", expected: enum.SortModeSize},
		{name: "created cookie", cookie: "created", expected: enum.SortModeCreated},
		{name: "invalid cookie returns default", cookie: "invalid", expected: enum.SortModeUpdated},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "sort_mode", Value: tc.cookie})
			}
			result := h.getSortMode(req)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestHandler_URL(t *testing.T) {
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
			h := newTestHandlerWithBaseURL(t, tc.baseURL)
			assert.Equal(t, tc.want, h.url(tc.path))
		})
	}
}

func TestHandler_CookiePath(t *testing.T) {
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
			h := newTestHandlerWithBaseURL(t, tc.baseURL)
			assert.Equal(t, tc.want, h.cookiePath())
		})
	}
}

func TestHandler_SortByMode(t *testing.T) {
	h := newTestHandler(t)
	now := time.Now()

	t.Run("sort by updated descending", func(t *testing.T) {
		keys := []keyWithPermission{
			{KeyInfo: store.KeyInfo{Key: "b", UpdatedAt: now.Add(-2 * time.Hour)}},
			{KeyInfo: store.KeyInfo{Key: "a", UpdatedAt: now}},
			{KeyInfo: store.KeyInfo{Key: "c", UpdatedAt: now.Add(-1 * time.Hour)}},
		}
		h.sortByMode(keys, enum.SortModeUpdated)
		assert.Equal(t, "a", keys[0].Key)
		assert.Equal(t, "c", keys[1].Key)
		assert.Equal(t, "b", keys[2].Key)
	})

	t.Run("sort by key ascending", func(t *testing.T) {
		keys := []keyWithPermission{
			{KeyInfo: store.KeyInfo{Key: "Zulu"}},
			{KeyInfo: store.KeyInfo{Key: "alpha"}},
			{KeyInfo: store.KeyInfo{Key: "Beta"}},
		}
		h.sortByMode(keys, enum.SortModeKey)
		assert.Equal(t, "alpha", keys[0].Key)
		assert.Equal(t, "Beta", keys[1].Key)
		assert.Equal(t, "Zulu", keys[2].Key)
	})

	t.Run("sort by size descending", func(t *testing.T) {
		keys := []keyWithPermission{
			{KeyInfo: store.KeyInfo{Key: "small", Size: 10}},
			{KeyInfo: store.KeyInfo{Key: "large", Size: 1000}},
			{KeyInfo: store.KeyInfo{Key: "medium", Size: 100}},
		}
		h.sortByMode(keys, enum.SortModeSize)
		assert.Equal(t, "large", keys[0].Key)
		assert.Equal(t, "medium", keys[1].Key)
		assert.Equal(t, "small", keys[2].Key)
	})

	t.Run("sort by created descending", func(t *testing.T) {
		keys := []keyWithPermission{
			{KeyInfo: store.KeyInfo{Key: "old", CreatedAt: now.Add(-2 * time.Hour)}},
			{KeyInfo: store.KeyInfo{Key: "new", CreatedAt: now}},
			{KeyInfo: store.KeyInfo{Key: "mid", CreatedAt: now.Add(-1 * time.Hour)}},
		}
		h.sortByMode(keys, enum.SortModeCreated)
		assert.Equal(t, "new", keys[0].Key)
		assert.Equal(t, "mid", keys[1].Key)
		assert.Equal(t, "old", keys[2].Key)
	})
}

func TestHandler_ValueForDisplay(t *testing.T) {
	h := newTestHandler(t)

	t.Run("utf8 passthrough", func(t *testing.T) {
		value, isBinary := h.valueForDisplay([]byte("hello world"))
		assert.Equal(t, "hello world", value)
		assert.False(t, isBinary)
	})

	t.Run("binary base64 encoding", func(t *testing.T) {
		binary := []byte{0x00, 0xFF, 0x80}
		value, isBinary := h.valueForDisplay(binary)
		assert.Equal(t, "AP+A", value)
		assert.True(t, isBinary)
	})

	t.Run("cyrillic text", func(t *testing.T) {
		value, isBinary := h.valueForDisplay([]byte("привет мир"))
		assert.Equal(t, "привет мир", value)
		assert.False(t, isBinary)
	})
}

func TestHandler_ValueFromForm(t *testing.T) {
	h := newTestHandler(t)

	t.Run("text decoding", func(t *testing.T) {
		value, err := h.valueFromForm("hello", false)
		require.NoError(t, err)
		assert.Equal(t, []byte("hello"), value)
	})

	t.Run("binary base64 decoding", func(t *testing.T) {
		value, err := h.valueFromForm("AP+A", true)
		require.NoError(t, err)
		assert.Equal(t, []byte{0x00, 0xFF, 0x80}, value)
	})

	t.Run("invalid base64 returns error", func(t *testing.T) {
		_, err := h.valueFromForm("not-valid-base64!!!", true)
		assert.Error(t, err)
	})
}

func TestHandler_FilterBySearch(t *testing.T) {
	h := newTestHandler(t)

	keys := []keyWithPermission{
		{KeyInfo: store.KeyInfo{Key: "config/db"}},
		{KeyInfo: store.KeyInfo{Key: "config/app"}},
		{KeyInfo: store.KeyInfo{Key: "secrets/api"}},
	}

	t.Run("empty search returns all", func(t *testing.T) {
		result := h.filterBySearch(keys, "")
		assert.Len(t, result, 3)
	})

	t.Run("filters by substring", func(t *testing.T) {
		result := h.filterBySearch(keys, "config")
		assert.Len(t, result, 2)
	})

	t.Run("case insensitive", func(t *testing.T) {
		result := h.filterBySearch(keys, "CONFIG")
		assert.Len(t, result, 2)
	})

	t.Run("no matches returns empty", func(t *testing.T) {
		result := h.filterBySearch(keys, "notfound")
		assert.Empty(t, result)
	})
}

func TestHandler_Paginate(t *testing.T) {
	h := newTestHandler(t)

	makeKeys := func(n int) []keyWithPermission {
		keys := make([]keyWithPermission, n)
		for i := range keys {
			keys[i] = keyWithPermission{KeyInfo: store.KeyInfo{Key: "key" + string(rune('a'+i))}}
		}
		return keys
	}

	tests := []struct {
		name      string
		keys      []keyWithPermission
		page      int
		pageSize  int
		wantLen   int
		wantPage  int
		wantTotal int
		wantPrev  bool
		wantNext  bool
	}{
		{name: "first", keys: makeKeys(10), page: 1, pageSize: 3, wantLen: 3, wantPage: 1, wantTotal: 4, wantPrev: false, wantNext: true},
		{name: "middle", keys: makeKeys(10), page: 2, pageSize: 3, wantLen: 3, wantPage: 2, wantTotal: 4, wantPrev: true, wantNext: true},
		{name: "last partial", keys: makeKeys(10), page: 4, pageSize: 3, wantLen: 1, wantPage: 4, wantTotal: 4, wantPrev: true, wantNext: false},
		{name: "beyond total", keys: makeKeys(10), page: 10, pageSize: 3, wantLen: 1, wantPage: 4, wantTotal: 4, wantPrev: true, wantNext: false},
		{name: "page zero", keys: makeKeys(10), page: 0, pageSize: 3, wantLen: 3, wantPage: 1, wantTotal: 4, wantPrev: false, wantNext: true},
		{name: "negative", keys: makeKeys(10), page: -5, pageSize: 3, wantLen: 3, wantPage: 1, wantTotal: 4, wantPrev: false, wantNext: true},
		{name: "empty keys", keys: nil, page: 1, pageSize: 3, wantLen: 0, wantPage: 1, wantTotal: 1, wantPrev: false, wantNext: false},
		{name: "exact fit", keys: makeKeys(6), page: 2, pageSize: 3, wantLen: 3, wantPage: 2, wantTotal: 2, wantPrev: true, wantNext: false},
		{name: "single", keys: makeKeys(2), page: 1, pageSize: 3, wantLen: 2, wantPage: 1, wantTotal: 1, wantPrev: false, wantNext: false},
		{name: "size zero", keys: makeKeys(5), page: 1, pageSize: 0, wantLen: 5, wantPage: 1, wantTotal: 1, wantPrev: false, wantNext: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pr := h.paginate(tc.keys, tc.page, tc.pageSize)
			assert.Len(t, pr.keys, tc.wantLen, "result length")
			assert.Equal(t, tc.wantPage, pr.page, "page")
			assert.Equal(t, tc.wantTotal, pr.totalPages, "totalPages")
			assert.Equal(t, tc.wantPrev, pr.hasPrev, "hasPrev")
			assert.Equal(t, tc.wantNext, pr.hasNext, "hasNext")
		})
	}
}

func TestHandler_FilterKeysByPermission(t *testing.T) {
	auth := &mocks.AuthProviderMock{
		FilterUserKeysFunc: func(username string, keys []string) []string {
			if username == "admin" {
				return keys // admin sees all
			}
			if username == "scoped" {
				// scoped user sees only app/*
				var filtered []string
				for _, k := range keys {
					if len(k) >= 4 && k[:4] == "app/" {
						filtered = append(filtered, k)
					}
				}
				return filtered
			}
			return nil // unknown user sees nothing
		},
		CheckUserPermissionFunc: func(username, key string, write bool) bool {
			if username == "admin" {
				return true
			}
			if username == "readonly" {
				return !write // can read but not write
			}
			if username == "scoped" {
				return len(key) >= 4 && key[:4] == "app/"
			}
			return false
		},
	}
	h := newTestHandlerWithAuth(t, auth)

	keys := []store.KeyInfo{
		{Key: "app/config", Size: 50},
		{Key: "app/db", Size: 100},
		{Key: "other/secret", Size: 200},
	}

	t.Run("admin sees all keys with write permission", func(t *testing.T) {
		result := h.filterKeysByPermission("admin", keys)
		assert.Len(t, result, 3)
		for _, k := range result {
			assert.True(t, k.CanWrite, "admin should have write permission for %s", k.Key)
		}
	})

	t.Run("scoped sees only allowed prefix with write permission", func(t *testing.T) {
		result := h.filterKeysByPermission("scoped", keys)
		assert.Len(t, result, 2)
		for _, k := range result {
			assert.True(t, k.CanWrite, "scoped should have write permission for %s", k.Key)
			assert.Contains(t, k.Key, "app/")
		}
	})

	t.Run("unknown user sees nothing", func(t *testing.T) {
		result := h.filterKeysByPermission("unknown", keys)
		assert.Empty(t, result)
	})
}

func TestHandler_CalculateModalDimensions(t *testing.T) {
	h := newTestHandler(t)

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
		{name: "empty", value: "", wantWidth: 600, wantHeight: 104},
		{name: "short", value: "hello", wantWidth: 600, wantHeight: 104},
		{name: "60 chars", value: "123456789012345678901234567890123456789012345678901234567890", wantWidth: 600, wantHeight: 104},
		{name: "max width", value: string(make([]byte, 200)), wantWidth: 1200, wantHeight: 104},
		{name: "few lines", value: "line1\nline2", wantWidth: 600, wantHeight: 104},
		{name: "10 lines", value: "1\n2\n3\n4\n5\n6\n7\n8\n9\n10", wantWidth: 600, wantHeight: 224},
		{name: "max height", value: "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20", wantWidth: 600, wantHeight: 384},
		{name: "cyrillic runes", value: "привет мир", wantWidth: 600, wantHeight: 104},
		{name: "japanese runes", value: "こんにちは世界", wantWidthMin: 600, wantWidthMax: 700, wantHeightMin: 104, wantHeightMax: 104},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			width, height := h.calculateModalDimensions(tc.value)
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

func TestHandler_GetCurrentUser(t *testing.T) {
	auth := &mocks.AuthProviderMock{
		GetSessionUserFunc: func(_ context.Context, token string) (string, bool) {
			if token == "valid-token" {
				return "testuser", true
			}
			return "", false
		},
	}
	h := newTestHandlerWithAuth(t, auth)

	t.Run("returns username from stash-auth cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "valid-token"})
		username := h.getCurrentUser(req)
		assert.Equal(t, "testuser", username)
	})

	t.Run("returns empty for no cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		username := h.getCurrentUser(req)
		assert.Empty(t, username)
	})

	t.Run("returns empty for invalid session", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "invalid-session"})
		username := h.getCurrentUser(req)
		assert.Empty(t, username)
	})
}

// defaultValidatorMock returns a validator mock with all methods implemented.
func defaultValidatorMock() *mocks.ValidatorMock {
	formats := []string{"text", "json", "yaml", "xml", "toml", "ini", "hcl", "shell"}
	return &mocks.ValidatorMock{
		ValidateFunc:         func(format string, value []byte) error { return nil },
		SupportedFormatsFunc: func() []string { return formats },
		IsValidFormatFunc: func(format string) bool {
			return slices.Contains(formats, format)
		},
	}
}

// newTestHandler creates a test handler with minimal mocks.
func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	st := &mocks.KVStoreMock{
		ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
	}
	auth := &mocks.AuthProviderMock{
		EnabledFunc:             func() bool { return false },
		GetSessionUserFunc:      func(_ context.Context, token string) (string, bool) { return "", false },
		FilterUserKeysFunc:      func(username string, keys []string) []string { return keys },
		CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		UserCanWriteFunc:        func(username string) bool { return true },
	}
	h, err := New(st, auth, defaultValidatorMock(), nil, Config{})
	require.NoError(t, err)
	return h
}

// newTestHandlerWithBaseURL creates a test handler with a specific base URL.
func newTestHandlerWithBaseURL(t *testing.T, baseURL string) *Handler {
	t.Helper()
	st := &mocks.KVStoreMock{
		ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
	}
	auth := &mocks.AuthProviderMock{
		EnabledFunc:             func() bool { return false },
		GetSessionUserFunc:      func(_ context.Context, token string) (string, bool) { return "", false },
		FilterUserKeysFunc:      func(username string, keys []string) []string { return keys },
		CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		UserCanWriteFunc:        func(username string) bool { return true },
	}
	h, err := New(st, auth, defaultValidatorMock(), nil, Config{BaseURL: baseURL})
	require.NoError(t, err)
	return h
}

func TestHandler_GetAuthor(t *testing.T) {
	h := newTestHandler(t)

	t.Run("empty username returns default author", func(t *testing.T) {
		author := h.getAuthor("")
		assert.Equal(t, "stash", author.Name)
		assert.Equal(t, "stash@localhost", author.Email)
	})

	t.Run("username creates author", func(t *testing.T) {
		author := h.getAuthor("testuser")
		assert.Equal(t, "testuser", author.Name)
		assert.Equal(t, "testuser@stash", author.Email)
	})

	t.Run("admin username creates admin author", func(t *testing.T) {
		author := h.getAuthor("admin")
		assert.Equal(t, "admin", author.Name)
		assert.Equal(t, "admin@stash", author.Email)
	})
}

// newTestHandlerWithAuth creates a test handler with a custom auth provider.
func newTestHandlerWithAuth(t *testing.T, auth AuthProvider) *Handler {
	t.Helper()
	st := &mocks.KVStoreMock{
		ListFunc: func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
	}
	h, err := New(st, auth, defaultValidatorMock(), nil, Config{})
	require.NoError(t, err)
	return h
}

// newTestHandlerWithGit creates a test handler with git service.
func newTestHandlerWithGit(t *testing.T, gitSvc GitService) *Handler {
	t.Helper()
	st := &mocks.KVStoreMock{
		ListFunc:          func(context.Context) ([]store.KeyInfo, error) { return nil, nil },
		GetWithFormatFunc: func(_ context.Context, key string) ([]byte, string, error) { return []byte("value"), "text", nil },
		SetFunc:           func(_ context.Context, key string, value []byte, format string) error { return nil },
	}
	auth := &mocks.AuthProviderMock{
		EnabledFunc:             func() bool { return false },
		GetSessionUserFunc:      func(_ context.Context, token string) (string, bool) { return "", false },
		FilterUserKeysFunc:      func(username string, keys []string) []string { return keys },
		CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		UserCanWriteFunc:        func(username string) bool { return true },
	}
	h, err := New(st, auth, defaultValidatorMock(), gitSvc, Config{})
	require.NoError(t, err)
	return h
}
