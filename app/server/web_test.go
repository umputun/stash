package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/mocks"
	"github.com/umputun/stash/app/store"
	"github.com/umputun/stash/app/validator"
)

func TestGetSortMode(t *testing.T) {
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
	srv := newTestServer(t, st)

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
			result := srv.getSortMode(req)
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
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
	srv := newTestServer(t, st)
	now := time.Now()

	t.Run("sort by updated descending", func(t *testing.T) {
		keys := []keyWithPermission{
			{KeyInfo: store.KeyInfo{Key: "b", UpdatedAt: now.Add(-2 * time.Hour)}},
			{KeyInfo: store.KeyInfo{Key: "a", UpdatedAt: now}},
			{KeyInfo: store.KeyInfo{Key: "c", UpdatedAt: now.Add(-1 * time.Hour)}},
		}
		srv.sortByMode(keys, "updated")
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
		srv.sortByMode(keys, "key")
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
		srv.sortByMode(keys, "size")
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
		srv.sortByMode(keys, "created")
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
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
	srv := newTestServer(t, st)

	t.Run("utf8 passthrough", func(t *testing.T) {
		value, isBinary := srv.valueForDisplay([]byte("hello world"))
		assert.Equal(t, "hello world", value)
		assert.False(t, isBinary)
	})

	t.Run("binary base64 encoding", func(t *testing.T) {
		binary := []byte{0x00, 0xFF, 0x80}
		value, isBinary := srv.valueForDisplay(binary)
		assert.Equal(t, "AP+A", value)
		assert.True(t, isBinary)
	})
}

func TestValueFromForm(t *testing.T) {
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
	srv := newTestServer(t, st)

	t.Run("text decoding", func(t *testing.T) {
		value, err := srv.valueFromForm("hello", false)
		require.NoError(t, err)
		assert.Equal(t, []byte("hello"), value)
	})

	t.Run("binary base64 decoding", func(t *testing.T) {
		value, err := srv.valueFromForm("AP+A", true)
		require.NoError(t, err)
		assert.Equal(t, []byte{0x00, 0xFF, 0x80}, value)
	})

	t.Run("invalid base64 returns error", func(t *testing.T) {
		_, err := srv.valueFromForm("not-valid-base64!!!", true)
		assert.Error(t, err)
	})
}

func TestFilterBySearch(t *testing.T) {
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
	srv := newTestServer(t, st)

	keys := []keyWithPermission{
		{KeyInfo: store.KeyInfo{Key: "config/db"}},
		{KeyInfo: store.KeyInfo{Key: "config/app"}},
		{KeyInfo: store.KeyInfo{Key: "secrets/api"}},
	}

	t.Run("empty search returns all", func(t *testing.T) {
		result := srv.filterBySearch(keys, "")
		assert.Len(t, result, 3)
	})

	t.Run("filters by substring", func(t *testing.T) {
		result := srv.filterBySearch(keys, "config")
		assert.Len(t, result, 2)
	})

	t.Run("case insensitive", func(t *testing.T) {
		result := srv.filterBySearch(keys, "CONFIG")
		assert.Len(t, result, 2)
	})

	t.Run("no matches returns empty", func(t *testing.T) {
		result := srv.filterBySearch(keys, "notfound")
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
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
	srv := newTestServer(t, st)

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
			assert.Equal(t, tc.expected, srv.getTheme(req))
		})
	}
}

func TestGetViewMode(t *testing.T) {
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
	srv := newTestServer(t, st)

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
			assert.Equal(t, tc.expected, srv.getViewMode(req))
		})
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

func TestPaginate(t *testing.T) {
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}
	srv := newTestServer(t, st)

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
		{name: "first page", keys: makeKeys(10), page: 1, pageSize: 3, wantLen: 3, wantPage: 1, wantTotal: 4, wantPrev: false, wantNext: true},
		{name: "middle page", keys: makeKeys(10), page: 2, pageSize: 3, wantLen: 3, wantPage: 2, wantTotal: 4, wantPrev: true, wantNext: true},
		{name: "last page partial", keys: makeKeys(10), page: 4, pageSize: 3, wantLen: 1, wantPage: 4, wantTotal: 4, wantPrev: true, wantNext: false},
		{name: "page beyond total clamps", keys: makeKeys(10), page: 10, pageSize: 3, wantLen: 1, wantPage: 4, wantTotal: 4, wantPrev: true, wantNext: false},
		{name: "page zero clamps to 1", keys: makeKeys(10), page: 0, pageSize: 3, wantLen: 3, wantPage: 1, wantTotal: 4, wantPrev: false, wantNext: true},
		{name: "negative page clamps to 1", keys: makeKeys(10), page: -5, pageSize: 3, wantLen: 3, wantPage: 1, wantTotal: 4, wantPrev: false, wantNext: true},
		{name: "empty keys", keys: nil, page: 1, pageSize: 3, wantLen: 0, wantPage: 1, wantTotal: 1, wantPrev: false, wantNext: false},
		{name: "exact page fit", keys: makeKeys(6), page: 2, pageSize: 3, wantLen: 3, wantPage: 2, wantTotal: 2, wantPrev: true, wantNext: false},
		{name: "single page", keys: makeKeys(2), page: 1, pageSize: 3, wantLen: 2, wantPage: 1, wantTotal: 1, wantPrev: false, wantNext: false},
		{name: "page size zero returns all", keys: makeKeys(5), page: 1, pageSize: 0, wantLen: 5, wantPage: 1, wantTotal: 1, wantPrev: false, wantNext: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, page, totalPages, hasPrev, hasNext := srv.paginate(tc.keys, tc.page, tc.pageSize)
			assert.Len(t, result, tc.wantLen, "result length")
			assert.Equal(t, tc.wantPage, page, "page")
			assert.Equal(t, tc.wantTotal, totalPages, "totalPages")
			assert.Equal(t, tc.wantPrev, hasPrev, "hasPrev")
			assert.Equal(t, tc.wantNext, hasNext, "hasNext")
		})
	}
}

func TestPageSize(t *testing.T) {
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return nil, nil }}

	t.Run("returns configured page size", func(t *testing.T) {
		srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, PageSize: 25})
		require.NoError(t, err)
		assert.Equal(t, 25, srv.pageSize())
	})

	t.Run("returns 0 (disabled) when set to 0", func(t *testing.T) {
		srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, PageSize: 0})
		require.NoError(t, err)
		assert.Equal(t, 0, srv.pageSize())
	})
}

func TestHandleIndexWithPagination(t *testing.T) {
	keys := make([]store.KeyInfo, 10)
	for i := range keys {
		keys[i] = store.KeyInfo{Key: "key" + string(rune('a'+i)), Size: 100}
	}
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return keys, nil }}
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, PageSize: 3})
	require.NoError(t, err)

	t.Run("first page", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		assert.Contains(t, body, "10 keys") // total count
		assert.Contains(t, body, "1 / 4")   // page indicator
	})

	t.Run("page 2 via query param", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/?page=2", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		assert.Contains(t, body, "2 / 4") // page indicator
	})
}

func TestHandleKeyListWithPagination(t *testing.T) {
	keys := make([]store.KeyInfo, 10)
	for i := range keys {
		keys[i] = store.KeyInfo{Key: "key" + string(rune('a'+i)), Size: 100}
	}
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return keys, nil }}
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, PageSize: 3})
	require.NoError(t, err)

	t.Run("first page of keys", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		assert.Contains(t, body, "keya")   // first key visible
		assert.Contains(t, body, "1 / 4")  // pagination OOB
		assert.Contains(t, body, "10 key") // total count OOB
	})

	t.Run("page 2 shows next keys", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/web/keys?page=2", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		assert.Contains(t, body, "keyd") // 4th key (index 3) visible on page 2
		assert.Contains(t, body, "2 / 4")
	})

	t.Run("search resets pagination context", func(t *testing.T) {
		// search for keys containing 'a' - should only find 'keya'
		req := httptest.NewRequest(http.MethodGet, "/web/keys?search=keya", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		body := rec.Body.String()
		assert.Contains(t, body, "keya")
		assert.Contains(t, body, `1 key`)
	})
}

func TestHandleKeyListPaginationDisabled(t *testing.T) {
	keys := make([]store.KeyInfo, 10)
	for i := range keys {
		keys[i] = store.KeyInfo{Key: "key" + string(rune('a'+i)), Size: 100}
	}
	st := &mocks.KVStoreMock{ListFunc: func() ([]store.KeyInfo, error) { return keys, nil }}
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, PageSize: 0})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	body := rec.Body.String()
	assert.Contains(t, body, "keya") // first key
	assert.Contains(t, body, "keyj") // last key (all 10 visible)
	assert.Contains(t, body, "10 keys")
	assert.NotContains(t, body, "1 / ") // no pagination controls
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
