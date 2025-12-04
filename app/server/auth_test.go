package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/server/mocks"
	"github.com/umputun/stash/app/store"
)

// testSessionStore creates an in-memory SQLite store for testing session operations.
func testSessionStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.New(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestPermission_CanRead(t *testing.T) {
	tests := []struct {
		perm enum.Permission
		want bool
	}{
		{enum.PermissionNone, false},
		{enum.PermissionRead, true},
		{enum.PermissionWrite, false},
		{enum.PermissionReadWrite, true},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.perm.CanRead(), "permission %v", tt.perm)
	}
}

func TestPermission_CanWrite(t *testing.T) {
	tests := []struct {
		perm enum.Permission
		want bool
	}{
		{enum.PermissionNone, false},
		{enum.PermissionRead, false},
		{enum.PermissionWrite, true},
		{enum.PermissionReadWrite, true},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.perm.CanWrite(), "permission %v", tt.perm)
	}
}

func TestPermission_String(t *testing.T) {
	tests := []struct {
		perm enum.Permission
		want string
	}{
		{enum.PermissionNone, "none"},
		{enum.PermissionRead, "read"},
		{enum.PermissionWrite, "write"},
		{enum.PermissionReadWrite, "readwrite"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.perm.String())
		})
	}
}

func TestLoadAuthConfig(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: "mytoken"
    permissions:
      - prefix: "*"
        access: r
`
		f := createTempFile(t, content)
		cfg, err := LoadAuthConfig(f)
		require.NoError(t, err)
		require.Len(t, cfg.Users, 1)
		require.Len(t, cfg.Tokens, 1)
		assert.Equal(t, "admin", cfg.Users[0].Name)
		assert.Equal(t, "mytoken", cfg.Tokens[0].Token)
	})

	t.Run("file not found", func(t *testing.T) {
		_, err := LoadAuthConfig("/nonexistent/file.yml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read auth config file")
	})

	t.Run("invalid yaml", func(t *testing.T) {
		f := createTempFile(t, "invalid: yaml: content:")
		_, err := LoadAuthConfig(f)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse auth config file")
	})
}

func TestNewAuth_Disabled(t *testing.T) {
	auth, err := NewAuth("", time.Hour, nil)
	require.NoError(t, err)
	assert.Nil(t, auth)
}

func TestNewAuth_Enabled(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: "apitoken"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)
	require.NotNil(t, auth)
	assert.True(t, auth.Enabled())
}

func TestNewAuth_Errors(t *testing.T) {
	t.Run("empty users and tokens", func(t *testing.T) {
		f := createTempFile(t, "users: []\ntokens: []")
		_, err := NewAuth(f, time.Hour, testSessionStore(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one user or token")
	})

	t.Run("empty user name", func(t *testing.T) {
		f := createTempFile(t, `users:
  - name: ""
    password: "hash"
    permissions:
      - prefix: "*"
        access: rw`)
		_, err := NewAuth(f, time.Hour, testSessionStore(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user name cannot be empty")
	})

	t.Run("empty password", func(t *testing.T) {
		f := createTempFile(t, `users:
  - name: "admin"
    password: ""
    permissions:
      - prefix: "*"
        access: rw`)
		_, err := NewAuth(f, time.Hour, testSessionStore(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "password hash cannot be empty")
	})

	t.Run("duplicate user", func(t *testing.T) {
		f := createTempFile(t, `users:
  - name: "admin"
    password: "hash1"
    permissions:
      - prefix: "*"
        access: rw
  - name: "admin"
    password: "hash2"
    permissions:
      - prefix: "*"
        access: r`)
		_, err := NewAuth(f, time.Hour, testSessionStore(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate user name")
	})

	t.Run("empty token", func(t *testing.T) {
		f := createTempFile(t, `tokens:
  - token: ""
    permissions:
      - prefix: "*"
        access: rw`)
		_, err := NewAuth(f, time.Hour, testSessionStore(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token cannot be empty")
	})

	t.Run("invalid permission", func(t *testing.T) {
		f := createTempFile(t, `users:
  - name: "admin"
    password: "hash"
    permissions:
      - prefix: "*"
        access: invalid`)
		_, err := NewAuth(f, time.Hour, testSessionStore(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "value must be one of")
	})

	t.Run("duplicate prefix", func(t *testing.T) {
		f := createTempFile(t, `users:
  - name: "admin"
    password: "hash"
    permissions:
      - prefix: "*"
        access: rw
      - prefix: "*"
        access: r`)
		_, err := NewAuth(f, time.Hour, testSessionStore(t))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate prefix")
	})
}

func TestAuth_ValidateUser(t *testing.T) {
	// bcrypt hash for "testpass"
	content := `
users:
  - name: admin
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	tests := []struct {
		name     string
		username string
		password string
		wantUser bool
	}{
		{"correct credentials", "admin", "testpass", true},
		{"wrong password", "admin", "wrong", false},
		{"unknown user", "unknown", "testpass", false},
		{"empty username", "", "testpass", false},
		{"empty password", "admin", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := auth.ValidateUser(tt.username, tt.password)
			if !tt.wantUser {
				assert.Nil(t, user)
				return
			}
			require.NotNil(t, user)
			assert.Equal(t, tt.username, user.Name)
		})
	}
}

func TestAuth_ValidateUser_NilAuth(t *testing.T) {
	var auth *Auth
	assert.Nil(t, auth.ValidateUser("admin", "pass"))
}

func TestMatchPrefix(t *testing.T) {
	tests := []struct {
		pattern string
		key     string
		want    bool
	}{
		{"*", "anything", true},
		{"*", "app/config", true},
		{"*", "", true},
		{"app/*", "app/config", true},
		{"app/*", "app/db/host", true},
		{"app/*", "app/", true},
		{"app/*", "application/config", false},
		{"app/*", "other/key", false},
		{"app/config", "app/config", true},
		{"app/config", "app/config/sub", false},
		{"app/config", "app/other", false},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.key, func(t *testing.T) {
			assert.Equal(t, tt.want, matchPrefix(tt.pattern, tt.key))
		})
	}
}

func TestTokenACL_CheckKeyPermission(t *testing.T) {
	acl := TokenACL{
		Token: "test",
		prefixes: []prefixPerm{
			{prefix: "app/*", permission: enum.PermissionReadWrite},
			{prefix: "*", permission: enum.PermissionRead},
		},
	}

	tests := []struct {
		key       string
		needWrite bool
		want      bool
	}{
		{"app/config", false, true},
		{"app/config", true, true},
		{"other/key", false, true},
		{"other/key", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			assert.Equal(t, tt.want, acl.CheckKeyPermission(tt.key, tt.needWrite))
		})
	}
}

func TestAuth_CheckPermission(t *testing.T) {
	content := `
tokens:
  - token: "full"
    permissions:
      - prefix: "*"
        access: rw
  - token: "readonly"
    permissions:
      - prefix: "*"
        access: r
  - token: "scoped"
    permissions:
      - prefix: "app/*"
        access: rw
      - prefix: "*"
        access: r
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	tests := []struct {
		token     string
		key       string
		needWrite bool
		want      bool
	}{
		{"full", "any/key", false, true},
		{"full", "any/key", true, true},
		{"readonly", "any/key", false, true},
		{"readonly", "any/key", true, false},
		{"scoped", "app/config", false, true},
		{"scoped", "app/config", true, true},
		{"scoped", "other/key", false, true},
		{"scoped", "other/key", true, false},
		{"unknown", "any", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.token+"_"+tt.key, func(t *testing.T) {
			got := auth.CheckPermission(tt.token, tt.key, tt.needWrite)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuth_CheckUserPermission(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
  - name: viewer
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: r
  - name: scoped
    password: "$2a$10$hash"
    permissions:
      - prefix: "app/*"
        access: rw
      - prefix: "*"
        access: r
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	tests := []struct {
		username  string
		key       string
		needWrite bool
		want      bool
	}{
		{"admin", "any/key", false, true},
		{"admin", "any/key", true, true},
		{"viewer", "any/key", false, true},
		{"viewer", "any/key", true, false},
		{"scoped", "app/config", true, true},
		{"scoped", "other/key", true, false},
		{"unknown", "any", false, false},
	}

	for _, tt := range tests {
		t.Run(tt.username+"_"+tt.key, func(t *testing.T) {
			got := auth.CheckUserPermission(tt.username, tt.key, tt.needWrite)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuth_FilterUserKeys(t *testing.T) {
	content := `
users:
  - name: scoped
    password: "$2a$10$hash"
    permissions:
      - prefix: "app/*"
        access: r
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	keys := []string{"app/config", "app/db", "other/key", "secret/data"}
	filtered := auth.FilterUserKeys("scoped", keys)
	assert.Equal(t, []string{"app/config", "app/db"}, filtered)

	// unknown user returns nil
	assert.Nil(t, auth.FilterUserKeys("unknown", keys))
}

func TestAuth_FilterUserKeys_NilAuth(t *testing.T) {
	var auth *Auth
	keys := []string{"a", "b"}
	assert.Equal(t, keys, auth.FilterUserKeys("any", keys))
}

func TestAuth_UserCanWrite(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
  - name: viewer
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: r
  - name: partial
    password: "$2a$10$hash"
    permissions:
      - prefix: "app/*"
        access: rw
      - prefix: "*"
        access: r
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	assert.True(t, auth.UserCanWrite("admin"))
	assert.False(t, auth.UserCanWrite("viewer"))
	assert.True(t, auth.UserCanWrite("partial"))
	assert.False(t, auth.UserCanWrite("unknown"))
}

func TestAuth_Session(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	// create session
	token, err := auth.CreateSession(t.Context(), "admin")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Len(t, token, 36) // uuid format

	// validate session
	assert.True(t, auth.ValidateSession(t.Context(), token))
	assert.False(t, auth.ValidateSession(t.Context(), "invalid"))

	// get session user
	username, valid := auth.GetSessionUser(t.Context(), token)
	assert.True(t, valid)
	assert.Equal(t, "admin", username)

	// invalid session
	_, valid = auth.GetSessionUser(t.Context(), "invalid")
	assert.False(t, valid)

	// invalidate session
	auth.InvalidateSession(t.Context(), token)
	assert.False(t, auth.ValidateSession(t.Context(), token))
}

func TestAuth_SessionExpiry(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, 50*time.Millisecond, testSessionStore(t))
	require.NoError(t, err)

	token, err := auth.CreateSession(t.Context(), "admin")
	require.NoError(t, err)

	// session should be valid immediately after creation
	assert.True(t, auth.ValidateSession(t.Context(), token))

	// wait for session to expire using Eventually to avoid flaky timing
	assert.Eventually(t, func() bool {
		return !auth.ValidateSession(t.Context(), token)
	}, 200*time.Millisecond, 10*time.Millisecond, "session should expire")

	// GetSessionUser also respects expiry
	_, valid := auth.GetSessionUser(t.Context(), token)
	assert.False(t, valid)
}

func TestAuth_CreateSession_NilAuth(t *testing.T) {
	var auth *Auth
	_, err := auth.CreateSession(t.Context(), "admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth not enabled")
}

func TestAuth_Enabled(t *testing.T) {
	var nilAuth *Auth
	assert.False(t, nilAuth.Enabled())

	content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)
	assert.True(t, auth.Enabled())
}

func TestAuth_LoginTTL(t *testing.T) {
	t.Run("nil auth returns default 30 days", func(t *testing.T) {
		var auth *Auth
		assert.Equal(t, 30*24*time.Hour, auth.LoginTTL())
	})

	t.Run("returns configured value", func(t *testing.T) {
		content := `users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw`
		f := createTempFile(t, content)
		auth, err := NewAuth(f, 2*time.Hour, testSessionStore(t))
		require.NoError(t, err)
		assert.Equal(t, 2*time.Hour, auth.LoginTTL())
	})
}

func TestNoopAuth(t *testing.T) {
	handler := NoopAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/anything", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuth_SessionAuth(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	middleware := auth.SessionAuth("/login")
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// without session should redirect to login
	req := httptest.NewRequest("GET", "/", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login", rec.Header().Get("Location"))

	// with valid session should pass
	token, err := auth.CreateSession(t.Context(), "admin")
	require.NoError(t, err)

	req = httptest.NewRequest("GET", "/", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "stash-auth", Value: token})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// HTMX request without session should return 401 with HX-Redirect header
	req = httptest.NewRequest("GET", "/web/keys", http.NoBody)
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "/login", rec.Header().Get("HX-Redirect"))
	assert.Empty(t, rec.Header().Get("Location"), "should not have Location header for HTMX")
}

func TestAuth_TokenAuth(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: "apitoken"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	handler := auth.TokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// without token should return 401
	req := httptest.NewRequest("GET", "/kv/test", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// with valid bearer token should pass
	req = httptest.NewRequest("GET", "/kv/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer apitoken")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// with invalid token should return 401
	req = httptest.NewRequest("GET", "/kv/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer invalid")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// session cookie should also work for API
	token, err := auth.CreateSession(t.Context(), "admin")
	require.NoError(t, err)

	req = httptest.NewRequest("GET", "/kv/test", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "stash-auth", Value: token})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuth_TokenAuth_Permissions(t *testing.T) {
	content := `
tokens:
  - token: "readonly"
    permissions:
      - prefix: "*"
        access: r
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	handler := auth.TokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// GET should work with read-only token
	req := httptest.NewRequest("GET", "/kv/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer readonly")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// PUT should fail with read-only token
	req = httptest.NewRequest("PUT", "/kv/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer readonly")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// DELETE should fail with read-only token
	req = httptest.NewRequest("DELETE", "/kv/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer readonly")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestAuth_TokenAuth_KeyNormalization(t *testing.T) {
	// ACL for "foo_bar" should match requests for "/kv/foo bar", "/kv/foo_bar/", etc.
	content := `
tokens:
  - token: "testtoken"
    permissions:
      - prefix: "foo_bar"
        access: rw
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	handler := auth.TokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name   string
		path   string
		expect int
	}{
		{"exact match", "/kv/foo_bar", http.StatusOK},
		{"space becomes underscore", "/kv/foo%20bar", http.StatusOK},
		{"trailing slash stripped", "/kv/foo_bar/", http.StatusOK},
		{"leading slash stripped", "/kv//foo_bar", http.StatusOK},
		{"combined normalization", "/kv//foo%20bar/", http.StatusOK},
		{"no match", "/kv/other", http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tc.path, http.NoBody)
			req.Header.Set("Authorization", "Bearer testtoken")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			assert.Equal(t, tc.expect, rec.Code)
		})
	}
}

func TestMaskToken(t *testing.T) {
	tests := []struct {
		token string
		want  string
	}{
		{"", "****"},
		{"a", "****"},
		{"abc", "****"},
		{"abcd", "****"},
		{"abcde", "abcd****"},
		{"longtoken123", "long****"},
	}
	for _, tt := range tests {
		t.Run(tt.token, func(t *testing.T) {
			assert.Equal(t, tt.want, maskToken(tt.token))
		})
	}
}

func TestAuth_GetTokenACL_NilAuth(t *testing.T) {
	var auth *Auth
	acl, ok := auth.GetTokenACL("anytoken")
	assert.False(t, ok)
	assert.Empty(t, acl.Token)
}

func TestParsePermissionString(t *testing.T) {
	tests := []struct {
		input   string
		want    enum.Permission
		wantErr bool
	}{
		{"r", enum.PermissionRead, false},
		{"R", enum.PermissionRead, false},
		{"read", enum.PermissionRead, false},
		{"w", enum.PermissionWrite, false},
		{"write", enum.PermissionWrite, false},
		{"rw", enum.PermissionReadWrite, false},
		{"RW", enum.PermissionReadWrite, false},
		{"readwrite", enum.PermissionReadWrite, false},
		{"read-write", enum.PermissionReadWrite, false},
		{"invalid", enum.PermissionNone, true},
		{"", enum.PermissionNone, true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parsePermissionString(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestTokenAuth_SessionCookieEnforcesACL verifies that session cookie auth
// on /kv API routes still enforces user permissions (not bypass ACL).
func TestTokenAuth_SessionCookieEnforcesACL(t *testing.T) {
	// bcrypt hash for "readonly123" with cost 4
	content := `
users:
  - name: readonly
    password: "$2a$04$N3p9HN1XKt7M8E0TBj9Jyex3aP8LXn4qGvYN8UxZJxU8aVH1Zf4kS"
    permissions:
      - prefix: "public/*"
        access: r
  - name: scoped
    password: "$2a$04$N3p9HN1XKt7M8E0TBj9Jyex3aP8LXn4qGvYN8UxZJxU8aVH1Zf4kS"
    permissions:
      - prefix: "app/*"
        access: rw
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	handler := auth.TokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// create session for read-only user
	sessionToken, err := auth.CreateSession(t.Context(), "readonly")
	require.NoError(t, err)

	t.Run("readonly user cannot PUT via session cookie", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/kv/public/test", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: sessionToken})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "read-only user should not be able to PUT")
	})

	t.Run("readonly user cannot DELETE via session cookie", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/kv/public/test", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: sessionToken})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "read-only user should not be able to DELETE")
	})

	t.Run("readonly user can read allowed prefix via session cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/kv/public/test", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: sessionToken})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "read-only user should be able to read public/*")
	})

	t.Run("readonly user cannot read outside allowed prefix via session cookie", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/kv/secret/key", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: sessionToken})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "read-only user should not access secret/*")
	})

	// create session for scoped user (app/* only)
	scopedSession, err := auth.CreateSession(t.Context(), "scoped")
	require.NoError(t, err)

	t.Run("scoped user can write to allowed prefix via session cookie", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/kv/app/config", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: scopedSession})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "scoped user should write to app/*")
	})

	t.Run("scoped user cannot write outside allowed prefix via session cookie", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/kv/secret/key", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: scopedSession})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "scoped user should not write to secret/*")
	})
}

// TestTokenAuth_PublicAccess verifies that token="*" grants public access without authentication.
func TestTokenAuth_PublicAccess(t *testing.T) {
	content := `
tokens:
  - token: "*"
    permissions:
      - prefix: "public/*"
        access: r
      - prefix: "status"
        access: r
  - token: "admin-token"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)
	require.NotNil(t, auth.publicACL, "public ACL should be set")

	handler := auth.TokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("anonymous can read public prefix", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/kv/public/config", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("anonymous can read exact public key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/kv/status", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("anonymous cannot write to public prefix", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/kv/public/config", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("anonymous cannot delete from public prefix", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/kv/public/config", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("anonymous cannot read private prefix", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/kv/private/secret", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("authenticated user can read private prefix", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/kv/private/secret", http.NoBody)
		req.Header.Set("Authorization", "Bearer admin-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("authenticated user can write to public prefix", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/kv/public/config", http.NoBody)
		req.Header.Set("Authorization", "Bearer admin-token")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestTokenAuth_PublicAccessWithWritePermission verifies public write access.
func TestTokenAuth_PublicAccessWithWritePermission(t *testing.T) {
	content := `
tokens:
  - token: "*"
    permissions:
      - prefix: "writable/*"
        access: rw
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	handler := auth.TokenAuth(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("anonymous can write to writable prefix", func(t *testing.T) {
		req := httptest.NewRequest("PUT", "/kv/writable/data", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("anonymous can delete from writable prefix", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/kv/writable/data", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("anonymous can read writable prefix", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/kv/writable/data", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

// TestParseTokenConfigs_PublicToken verifies that "*" token is extracted correctly.
func TestParseTokenConfigs_PublicToken(t *testing.T) {
	t.Run("public token extracted separately", func(t *testing.T) {
		configs := []TokenConfig{
			{Token: "*", Permissions: []PermissionConfig{{Prefix: "public/*", Access: "r"}}},
			{Token: "normal", Permissions: []PermissionConfig{{Prefix: "*", Access: "rw"}}},
		}
		tokens, publicACL, err := parseTokenConfigs(configs)
		require.NoError(t, err)
		require.NotNil(t, publicACL, "public ACL should be extracted")
		assert.Len(t, tokens, 1, "only normal token should be in map")
		_, hasPublic := tokens["*"]
		assert.False(t, hasPublic, "* should not be in tokens map")
		_, hasNormal := tokens["normal"]
		assert.True(t, hasNormal, "normal token should be in map")
	})

	t.Run("only public token", func(t *testing.T) {
		configs := []TokenConfig{
			{Token: "*", Permissions: []PermissionConfig{{Prefix: "*", Access: "r"}}},
		}
		tokens, publicACL, err := parseTokenConfigs(configs)
		require.NoError(t, err)
		require.NotNil(t, publicACL)
		assert.Empty(t, tokens, "tokens map should be empty")
	})

	t.Run("no public token", func(t *testing.T) {
		configs := []TokenConfig{
			{Token: "normal", Permissions: []PermissionConfig{{Prefix: "*", Access: "rw"}}},
		}
		tokens, publicACL, err := parseTokenConfigs(configs)
		require.NoError(t, err)
		assert.Nil(t, publicACL, "public ACL should be nil")
		assert.Len(t, tokens, 1)
	})

	t.Run("duplicate public token rejected", func(t *testing.T) {
		configs := []TokenConfig{
			{Token: "*", Permissions: []PermissionConfig{{Prefix: "public/*", Access: "r"}}},
			{Token: "*", Permissions: []PermissionConfig{{Prefix: "status", Access: "r"}}},
		}
		_, _, err := parseTokenConfigs(configs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate public token")
	})
}

// TestNewAuth_PublicTokenOnly verifies auth can be created with only public token.
func TestNewAuth_PublicTokenOnly(t *testing.T) {
	content := `
tokens:
  - token: "*"
    permissions:
      - prefix: "*"
        access: r
`
	f := createTempFile(t, content)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)
	require.NotNil(t, auth)
	require.NotNil(t, auth.publicACL)
	assert.Empty(t, auth.tokens)
	assert.Empty(t, auth.users)
}

// createTempFile creates a temporary file with the given content and returns its path.
func createTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	f := filepath.Join(dir, "auth.yml")
	err := os.WriteFile(f, []byte(content), 0o600)
	require.NoError(t, err)
	return f
}

func TestAuth_Reload(t *testing.T) {
	initialConfig := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: "token1"
    permissions:
      - prefix: "*"
        access: r
`
	f := createTempFile(t, initialConfig)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	// verify initial config
	assert.True(t, auth.HasTokenACL("token1"))
	assert.False(t, auth.HasTokenACL("token2"))

	// create a session
	session, err := auth.CreateSession(t.Context(), "admin")
	require.NoError(t, err)
	assert.True(t, auth.ValidateSession(t.Context(), session))

	// update config file with new token
	newConfig := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
  - name: viewer
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: r
tokens:
  - token: "token2"
    permissions:
      - prefix: "*"
        access: rw
`
	err = os.WriteFile(f, []byte(newConfig), 0o600)
	require.NoError(t, err)

	// reload config
	err = auth.Reload(t.Context())
	require.NoError(t, err)

	// verify new config is loaded
	assert.False(t, auth.HasTokenACL("token1"), "old token should be gone")
	assert.True(t, auth.HasTokenACL("token2"), "new token should exist")

	// verify session is preserved (admin user unchanged)
	assert.True(t, auth.ValidateSession(t.Context(), session), "session should be preserved for unchanged user")

	// verify new user exists
	assert.True(t, auth.CheckUserPermission("viewer", "test", false))
}

func TestAuth_Reload_InvalidConfig(t *testing.T) {
	initialConfig := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, initialConfig)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	// verify initial state
	assert.True(t, auth.CheckUserPermission("admin", "test", true))

	// write invalid config
	err = os.WriteFile(f, []byte("invalid: yaml: content:"), 0o600)
	require.NoError(t, err)

	// reload should fail
	err = auth.Reload(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load auth config")

	// original config should still work
	assert.True(t, auth.CheckUserPermission("admin", "test", true))
}

func TestAuth_Reload_EmptyConfig(t *testing.T) {
	initialConfig := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, initialConfig)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	// write empty config (no users or tokens)
	err = os.WriteFile(f, []byte("users: []\ntokens: []"), 0o600)
	require.NoError(t, err)

	// reload should fail
	err = auth.Reload(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one user or token")

	// original config should still work
	assert.True(t, auth.CheckUserPermission("admin", "test", true))
}

func TestAuth_Reload_NilAuth(t *testing.T) {
	var auth *Auth
	err := auth.Reload(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth not enabled")
}

func TestAuth_Reload_SelectiveSessionInvalidation(t *testing.T) {
	tests := []struct {
		name          string
		initialConfig string
		updatedConfig string
		sessions      []string // usernames to create sessions for
		expectValid   []string // usernames whose sessions should remain valid
		expectInvalid []string // usernames whose sessions should be invalidated
	}{
		{
			name: "user removed - sessions invalidated",
			initialConfig: `users:
  - name: alice
    password: "$2a$10$hash1"
    permissions: [{prefix: "*", access: rw}]
  - name: bob
    password: "$2a$10$hash2"
    permissions: [{prefix: "*", access: r}]`,
			updatedConfig: `users:
  - name: bob
    password: "$2a$10$hash2"
    permissions: [{prefix: "*", access: r}]`,
			sessions:      []string{"alice", "bob"},
			expectValid:   []string{"bob"},
			expectInvalid: []string{"alice"},
		},
		{
			name: "password changed - sessions invalidated",
			initialConfig: `users:
  - name: alice
    password: "$2a$10$oldhash"
    permissions: [{prefix: "*", access: rw}]`,
			updatedConfig: `users:
  - name: alice
    password: "$2a$10$newhash"
    permissions: [{prefix: "*", access: rw}]`,
			sessions:      []string{"alice"},
			expectValid:   []string{},
			expectInvalid: []string{"alice"},
		},
		{
			name: "permissions changed only - sessions preserved",
			initialConfig: `users:
  - name: alice
    password: "$2a$10$hash"
    permissions: [{prefix: "*", access: rw}]`,
			updatedConfig: `users:
  - name: alice
    password: "$2a$10$hash"
    permissions: [{prefix: "readonly/*", access: r}]`,
			sessions:      []string{"alice"},
			expectValid:   []string{"alice"},
			expectInvalid: []string{},
		},
		{
			name: "unchanged config - all sessions preserved",
			initialConfig: `users:
  - name: alice
    password: "$2a$10$hash"
    permissions: [{prefix: "*", access: rw}]`,
			updatedConfig: `users:
  - name: alice
    password: "$2a$10$hash"
    permissions: [{prefix: "*", access: rw}]`,
			sessions:      []string{"alice"},
			expectValid:   []string{"alice"},
			expectInvalid: []string{},
		},
		{
			name: "new user added - existing sessions preserved",
			initialConfig: `users:
  - name: alice
    password: "$2a$10$hash"
    permissions: [{prefix: "*", access: rw}]`,
			updatedConfig: `users:
  - name: alice
    password: "$2a$10$hash"
    permissions: [{prefix: "*", access: rw}]
  - name: bob
    password: "$2a$10$hash2"
    permissions: [{prefix: "*", access: r}]`,
			sessions:      []string{"alice"},
			expectValid:   []string{"alice"},
			expectInvalid: []string{},
		},
		{
			name: "mixed changes - selective invalidation",
			initialConfig: `users:
  - name: alice
    password: "$2a$10$hash1"
    permissions: [{prefix: "*", access: rw}]
  - name: bob
    password: "$2a$10$oldhash"
    permissions: [{prefix: "*", access: rw}]
  - name: carol
    password: "$2a$10$hash3"
    permissions: [{prefix: "*", access: r}]`,
			updatedConfig: `users:
  - name: alice
    password: "$2a$10$hash1"
    permissions: [{prefix: "new/*", access: rw}]
  - name: bob
    password: "$2a$10$newhash"
    permissions: [{prefix: "*", access: rw}]`,
			sessions:      []string{"alice", "bob", "carol"},
			expectValid:   []string{"alice"},        // unchanged (only perms changed)
			expectInvalid: []string{"bob", "carol"}, // bob: password changed, carol: removed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := createTempFile(t, tt.initialConfig)
			auth, err := NewAuth(f, time.Hour, testSessionStore(t))
			require.NoError(t, err)

			// create sessions and track tokens
			tokensByUser := make(map[string]string)
			for _, username := range tt.sessions {
				token, createErr := auth.CreateSession(t.Context(), username)
				require.NoError(t, createErr)
				tokensByUser[username] = token
			}

			// reload with updated config
			err = os.WriteFile(f, []byte(tt.updatedConfig), 0o600)
			require.NoError(t, err)
			err = auth.Reload(t.Context())
			require.NoError(t, err)

			// verify expected valid sessions
			for _, username := range tt.expectValid {
				token := tokensByUser[username]
				assert.True(t, auth.ValidateSession(t.Context(), token),
					"session for %q should remain valid", username)
			}

			// verify expected invalid sessions
			for _, username := range tt.expectInvalid {
				token := tokensByUser[username]
				assert.False(t, auth.ValidateSession(t.Context(), token),
					"session for %q should be invalidated", username)
			}
		})
	}
}

func TestAuth_Reload_DeleteSessionsByUsernameError(t *testing.T) {
	initialConfig := `users:
  - name: alice
    password: "$2a$10$hash1"
    permissions: [{prefix: "*", access: rw}]
  - name: bob
    password: "$2a$10$hash2"
    permissions: [{prefix: "*", access: r}]`

	updatedConfig := `users:
  - name: alice
    password: "$2a$10$newhash"
    permissions: [{prefix: "*", access: rw}]`

	f := createTempFile(t, initialConfig)

	// track calls and return error for alice
	var deletedUsers []string
	mockStore := &mocks.SessionStoreMock{
		CreateSessionFunc: func(_ context.Context, token, username string, expiresAt time.Time) error {
			return nil
		},
		GetSessionFunc: func(_ context.Context, token string) (string, time.Time, error) {
			return "", time.Time{}, store.ErrNotFound
		},
		DeleteSessionsByUsernameFunc: func(_ context.Context, username string) error {
			deletedUsers = append(deletedUsers, username)
			if username == "alice" {
				return errors.New("database connection lost")
			}
			return nil
		},
	}

	auth, err := NewAuth(f, time.Hour, mockStore)
	require.NoError(t, err)

	// update config to trigger session invalidation for both users
	err = os.WriteFile(f, []byte(updatedConfig), 0o600)
	require.NoError(t, err)

	// reload should succeed despite DeleteSessionsByUsername error
	err = auth.Reload(t.Context())
	require.NoError(t, err, "reload should succeed even when session deletion fails")

	// verify both users were attempted (alice: password changed, bob: removed)
	assert.ElementsMatch(t, []string{"alice", "bob"}, deletedUsers,
		"should attempt to delete sessions for both changed users")

	// verify config was updated despite error
	assert.False(t, auth.CheckUserPermission("bob", "test", false),
		"bob should be removed from config")
	assert.True(t, auth.CheckUserPermission("alice", "test", false),
		"alice should still exist in config")
}

func TestAuth_ConcurrentAccess(t *testing.T) {
	config := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: "apitoken"
    permissions:
      - prefix: "*"
        access: r
`
	f := createTempFile(t, config)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	// run concurrent reads and reloads
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			_ = auth.Reload(t.Context())
		}
	}()

	// concurrent reads while reloading
	for range 1000 {
		_ = auth.Enabled()
		_ = auth.HasTokenACL("apitoken")
		_ = auth.CheckUserPermission("admin", "test", false)
		_ = auth.FilterUserKeys("admin", []string{"a", "b", "c"})
		_ = auth.FilterTokenKeys("apitoken", []string{"a", "b", "c"})
		_ = auth.UserCanWrite("admin")
	}

	<-done
}

func TestAuth_StartWatcher(t *testing.T) {
	config := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: "token1"
    permissions:
      - prefix: "*"
        access: r
`
	f := createTempFile(t, config)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	err = auth.StartWatcher(t.Context())
	require.NoError(t, err)

	// verify initial config
	assert.True(t, auth.HasTokenACL("token1"))
	assert.False(t, auth.HasTokenACL("token2"))

	// update config file
	newConfig := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: "token2"
    permissions:
      - prefix: "*"
        access: rw
`
	err = os.WriteFile(f, []byte(newConfig), 0o600)
	require.NoError(t, err)

	// wait for reload using Eventually (avoids flaky timing)
	require.Eventually(t, func() bool {
		return auth.HasTokenACL("token2")
	}, 2*time.Second, 10*time.Millisecond, "new token should exist after reload")

	// verify old token is gone
	assert.False(t, auth.HasTokenACL("token1"), "old token should be gone")
}

func TestAuth_StartWatcher_AtomicRename(t *testing.T) {
	config := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	dir := t.TempDir()
	authFile := filepath.Join(dir, "auth.yml")
	err := os.WriteFile(authFile, []byte(config), 0o600)
	require.NoError(t, err)

	auth, err := NewAuth(authFile, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	err = auth.StartWatcher(t.Context())
	require.NoError(t, err)

	// verify initial config
	assert.True(t, auth.CheckUserPermission("admin", "test", true))
	assert.False(t, auth.CheckUserPermission("newuser", "test", false))

	// simulate vim-style save: write temp file then rename
	newConfig := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
  - name: newuser
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: r
`
	tmpFile := filepath.Join(dir, "auth.yml.tmp")
	err = os.WriteFile(tmpFile, []byte(newConfig), 0o600)
	require.NoError(t, err)
	err = os.Rename(tmpFile, authFile)
	require.NoError(t, err)

	// wait for reload using Eventually (avoids flaky timing)
	require.Eventually(t, func() bool {
		return auth.CheckUserPermission("newuser", "test", false)
	}, 2*time.Second, 10*time.Millisecond, "new user should exist after rename")
}

func TestAuth_StartWatcher_ContextCancel(t *testing.T) {
	config := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, config)
	auth, err := NewAuth(f, time.Hour, testSessionStore(t))
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	err = auth.StartWatcher(ctx)
	require.NoError(t, err)

	// cancel the context
	cancel()

	// give the goroutine time to clean up
	time.Sleep(50 * time.Millisecond)

	// further file changes should not trigger reload
	// (we can't easily verify this, but at least verify no panic/crash)
}

func TestAuth_StartWatcher_NilAuth(t *testing.T) {
	var auth *Auth
	err := auth.StartWatcher(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth not enabled")
}

func TestAuth_StartWatcher_EmptyAuthFile(t *testing.T) {
	auth := &Auth{
		authFile:     "",
		users:        make(map[string]User),
		tokens:       make(map[string]TokenACL),
		sessionStore: testSessionStore(t),
	}
	err := auth.StartWatcher(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth file path not set")
}

func TestAuth_StartCleanup(t *testing.T) {
	t.Run("cleanup stops on context cancel", func(t *testing.T) {
		ss := testSessionStore(t)
		auth := &Auth{
			users:           make(map[string]User),
			tokens:          make(map[string]TokenACL),
			sessionStore:    ss,
			cleanupInterval: 50 * time.Millisecond,
		}

		ctx, cancel := context.WithCancel(context.Background())
		auth.StartCleanup(ctx)

		// cancel immediately - cleanup should stop gracefully
		cancel()
		time.Sleep(100 * time.Millisecond) // give goroutine time to stop
	})

	t.Run("cleanup deletes expired sessions", func(t *testing.T) {
		ss := testSessionStore(t)
		ctx := t.Context()

		// create expired session
		expired := time.Now().Add(-time.Hour).UTC()
		err := ss.CreateSession(ctx, "expired-token", "user", expired)
		require.NoError(t, err)

		// create valid session
		valid := time.Now().Add(time.Hour).UTC()
		err = ss.CreateSession(ctx, "valid-token", "user", valid)
		require.NoError(t, err)

		// start cleanup with short interval
		auth := &Auth{
			users:           make(map[string]User),
			tokens:          make(map[string]TokenACL),
			sessionStore:    ss,
			cleanupInterval: 50 * time.Millisecond,
		}

		cleanupCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		auth.StartCleanup(cleanupCtx)

		// wait for at least 2 cleanup cycles
		time.Sleep(150 * time.Millisecond)

		// verify expired session was deleted by cleanup (not by our test code).
		// if we call DeleteExpiredSessions now, it should return 0 because cleanup already handled it.
		deleted, err := ss.DeleteExpiredSessions(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(0), deleted, "cleanup should have already deleted expired sessions")

		// valid session should remain
		_, _, err = ss.GetSession(ctx, "valid-token")
		require.NoError(t, err)
	})

	t.Run("nil auth is noop", func(t *testing.T) {
		var auth *Auth
		auth.StartCleanup(context.Background()) // should not panic
	})
}
