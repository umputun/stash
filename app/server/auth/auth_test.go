package auth

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

	"github.com/umputun/stash/app/server/auth/mocks"
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

func TestNew_Disabled(t *testing.T) {
	svc, err := New("", time.Hour, false, nil, nil)
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestNew_Enabled(t *testing.T) {
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
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.True(t, svc.Enabled())
}

func TestNew_Errors(t *testing.T) {
	t.Run("empty users and tokens", func(t *testing.T) {
		f := createTempFile(t, "users: []\ntokens: []")
		_, err := New(f, time.Hour, false, testSessionStore(t), nil)
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
		_, err := New(f, time.Hour, false, testSessionStore(t), nil)
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
		_, err := New(f, time.Hour, false, testSessionStore(t), nil)
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
		_, err := New(f, time.Hour, false, testSessionStore(t), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate user name")
	})

	t.Run("empty token", func(t *testing.T) {
		f := createTempFile(t, `tokens:
  - token: ""
    permissions:
      - prefix: "*"
        access: rw`)
		_, err := New(f, time.Hour, false, testSessionStore(t), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "token cannot be empty")
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
		_, err := New(f, time.Hour, false, testSessionStore(t), nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate prefix")
	})

	t.Run("session store required", func(t *testing.T) {
		f := createTempFile(t, `users:
  - name: "admin"
    password: "hash"
    permissions:
      - prefix: "*"
        access: rw`)
		_, err := New(f, time.Hour, false, nil, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "session store is required")
	})
}

func TestNew_PublicTokenOnly(t *testing.T) {
	content := `
tokens:
  - token: "*"
    permissions:
      - prefix: "*"
        access: r
`
	f := createTempFile(t, content)
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.True(t, svc.Enabled()) // public ACL means auth is enabled
	assert.Empty(t, svc.tokens)
	assert.Empty(t, svc.users)
}

func TestService_Activate(t *testing.T) {
	t.Run("nil service returns nil", func(t *testing.T) {
		var svc *Service
		err := svc.Activate(t.Context())
		assert.NoError(t, err)
	})

	t.Run("activates without hot-reload", func(t *testing.T) {
		content := `
users:
  - name: admin
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
`
		f := createTempFile(t, content)
		svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(t.Context())
		err = svc.Activate(ctx)
		require.NoError(t, err)

		cancel() // stop background goroutines
	})

	t.Run("activates with hot-reload", func(t *testing.T) {
		content := `
users:
  - name: admin
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
`
		f := createTempFile(t, content)
		svc, err := New(f, time.Hour, true, testSessionStore(t), nil)
		require.NoError(t, err)

		ctx, cancel := context.WithCancel(t.Context())
		err = svc.Activate(ctx)
		require.NoError(t, err)

		cancel() // stop background goroutines (watcher + cleanup)
	})
}

func TestService_IsValidUser(t *testing.T) {
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
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	tests := []struct {
		name     string
		username string
		password string
		want     bool
	}{
		{"correct credentials", "admin", "testpass", true},
		{"wrong password", "admin", "wrong", false},
		{"unknown user", "unknown", "testpass", false},
		{"empty username", "", "testpass", false},
		{"empty password", "admin", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, svc.IsValidUser(tt.username, tt.password))
		})
	}
}

func TestService_IsValidUser_NilService(t *testing.T) {
	var svc *Service
	assert.False(t, svc.IsValidUser("admin", "pass"))
}

func TestService_checkPermission(t *testing.T) {
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
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
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
			got := svc.checkPermission(tt.token, tt.key, tt.needWrite)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestService_CheckUserPermission(t *testing.T) {
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
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
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
			got := svc.CheckUserPermission(tt.username, tt.key, tt.needWrite)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestService_FilterUserKeys(t *testing.T) {
	content := `
users:
  - name: scoped
    password: "$2a$10$hash"
    permissions:
      - prefix: "app/*"
        access: r
`
	f := createTempFile(t, content)
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	keys := []string{"app/config", "app/db", "other/key", "secret/data"}
	filtered := svc.FilterUserKeys("scoped", keys)
	assert.Equal(t, []string{"app/config", "app/db"}, filtered)

	// unknown user returns nil
	assert.Nil(t, svc.FilterUserKeys("unknown", keys))
}

func TestService_FilterUserKeys_NilService(t *testing.T) {
	var svc *Service
	keys := []string{"a", "b"}
	assert.Equal(t, keys, svc.FilterUserKeys("any", keys))
}

func TestService_UserCanWrite(t *testing.T) {
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
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	assert.True(t, svc.UserCanWrite("admin"))
	assert.False(t, svc.UserCanWrite("viewer"))
	assert.True(t, svc.UserCanWrite("partial"))
	assert.False(t, svc.UserCanWrite("unknown"))
}

func TestService_Session(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	// create session
	token, err := svc.CreateSession(t.Context(), "admin")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Len(t, token, 36) // uuid format

	// get session user
	username, valid := svc.GetSessionUser(t.Context(), token)
	assert.True(t, valid)
	assert.Equal(t, "admin", username)

	// invalid session
	_, valid = svc.GetSessionUser(t.Context(), "invalid")
	assert.False(t, valid)

	// invalidate session
	svc.InvalidateSession(t.Context(), token)
	_, valid = svc.GetSessionUser(t.Context(), token)
	assert.False(t, valid)
}

func TestService_SessionExpiry(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	svc, err := New(f, 50*time.Millisecond, false, testSessionStore(t), nil)
	require.NoError(t, err)

	token, err := svc.CreateSession(t.Context(), "admin")
	require.NoError(t, err)

	// session should be valid immediately after creation
	_, valid := svc.GetSessionUser(t.Context(), token)
	assert.True(t, valid)

	// wait for session to expire using Eventually to avoid flaky timing
	assert.Eventually(t, func() bool {
		_, ok := svc.GetSessionUser(t.Context(), token)
		return !ok
	}, 200*time.Millisecond, 10*time.Millisecond, "session should expire")

	// GetSessionUser also respects expiry
	_, valid = svc.GetSessionUser(t.Context(), token)
	assert.False(t, valid)
}

func TestService_CreateSession_NilService(t *testing.T) {
	var svc *Service
	_, err := svc.CreateSession(t.Context(), "admin")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth not enabled")
}

func TestService_Enabled(t *testing.T) {
	var nilSvc *Service
	assert.False(t, nilSvc.Enabled())

	content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)
	assert.True(t, svc.Enabled())
}

func TestService_LoginTTL(t *testing.T) {
	t.Run("nil service returns default 30 days", func(t *testing.T) {
		var svc *Service
		assert.Equal(t, 30*24*time.Hour, svc.LoginTTL())
	})

	t.Run("returns configured value", func(t *testing.T) {
		content := `users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw`
		f := createTempFile(t, content)
		svc, err := New(f, 2*time.Hour, false, testSessionStore(t), nil)
		require.NoError(t, err)
		assert.Equal(t, 2*time.Hour, svc.LoginTTL())
	})
}

func TestService_getTokenACL_NilService(t *testing.T) {
	var svc *Service
	acl, ok := svc.getTokenACL("anytoken")
	assert.False(t, ok)
	assert.Empty(t, acl.Token)
}

func TestService_IsAdmin(t *testing.T) {
	t.Run("admin user", func(t *testing.T) {
		content := `
users:
  - name: admin
    password: "$2a$10$C615A0mfUEFBupj9qcqhiuBEyf60EqrsakB90CozUoSON8d2Dc1uS"
    admin: true
    permissions:
      - prefix: "*"
        access: rw
  - name: regular
    password: "$2a$10$C615A0mfUEFBupj9qcqhiuBEyf60EqrsakB90CozUoSON8d2Dc1uS"
    permissions:
      - prefix: "*"
        access: r
`
		f := createTempFile(t, content)
		ss := testSessionStore(t)
		svc, err := New(f, time.Hour, false, ss, nil)
		require.NoError(t, err)

		assert.True(t, svc.IsAdmin("admin"), "admin user should be admin")
		assert.False(t, svc.IsAdmin("regular"), "regular user should not be admin")
		assert.False(t, svc.IsAdmin("unknown"), "unknown user should not be admin")
	})

	t.Run("nil service", func(t *testing.T) {
		var svc *Service
		assert.False(t, svc.IsAdmin("anyone"), "nil service should return false")
	})
}

func TestService_isTokenAdmin(t *testing.T) {
	t.Run("admin token", func(t *testing.T) {
		content := `
tokens:
  - token: "admin-token"
    admin: true
    permissions:
      - prefix: "*"
        access: rw
  - token: "regular-token"
    permissions:
      - prefix: "*"
        access: r
`
		f := createTempFile(t, content)
		ss := testSessionStore(t)
		svc, err := New(f, time.Hour, false, ss, nil)
		require.NoError(t, err)

		assert.True(t, svc.isTokenAdmin("admin-token"), "admin token should return true")
		assert.False(t, svc.isTokenAdmin("regular-token"), "non-admin token should return false")
		assert.False(t, svc.isTokenAdmin("unknown-token"), "unknown token should return false")
	})

	t.Run("nil service", func(t *testing.T) {
		var svc *Service
		assert.False(t, svc.isTokenAdmin("any-token"), "nil service should return false")
	})
}

func TestService_Reload(t *testing.T) {
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
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	// verify initial config
	assert.True(t, svc.hasTokenACL("token1"))
	assert.False(t, svc.hasTokenACL("token2"))

	// create a session
	session, err := svc.CreateSession(t.Context(), "admin")
	require.NoError(t, err)
	_, ok := svc.GetSessionUser(t.Context(), session)
	assert.True(t, ok)

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
	err = svc.Reload(t.Context())
	require.NoError(t, err)

	// verify new config is loaded
	assert.False(t, svc.hasTokenACL("token1"), "old token should be gone")
	assert.True(t, svc.hasTokenACL("token2"), "new token should exist")

	// verify session is preserved (admin user unchanged)
	_, ok = svc.GetSessionUser(t.Context(), session)
	assert.True(t, ok, "session should be preserved for unchanged user")

	// verify new user exists
	assert.True(t, svc.CheckUserPermission("viewer", "test", false))
}

func TestService_Reload_InvalidConfig(t *testing.T) {
	initialConfig := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, initialConfig)
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	// verify initial state
	assert.True(t, svc.CheckUserPermission("admin", "test", true))

	// write invalid config
	err = os.WriteFile(f, []byte("invalid: yaml: content:"), 0o600)
	require.NoError(t, err)

	// reload should fail
	err = svc.Reload(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to load auth config")

	// original config should still work
	assert.True(t, svc.CheckUserPermission("admin", "test", true))
}

func TestService_Reload_EmptyConfig(t *testing.T) {
	initialConfig := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, initialConfig)
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	// write empty config (no users or tokens)
	err = os.WriteFile(f, []byte("users: []\ntokens: []"), 0o600)
	require.NoError(t, err)

	// reload should fail
	err = svc.Reload(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one user or token")

	// original config should still work
	assert.True(t, svc.CheckUserPermission("admin", "test", true))
}

func TestService_Reload_NilService(t *testing.T) {
	var svc *Service
	err := svc.Reload(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth not enabled")
}

func TestService_Reload_SelectiveSessionInvalidation(t *testing.T) {
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
			svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
			require.NoError(t, err)

			// create sessions and track tokens
			tokensByUser := make(map[string]string)
			for _, username := range tt.sessions {
				token, createErr := svc.CreateSession(t.Context(), username)
				require.NoError(t, createErr)
				tokensByUser[username] = token
			}

			// reload with updated config
			err = os.WriteFile(f, []byte(tt.updatedConfig), 0o600)
			require.NoError(t, err)
			err = svc.Reload(t.Context())
			require.NoError(t, err)

			// verify expected valid sessions
			for _, username := range tt.expectValid {
				token := tokensByUser[username]
				_, ok := svc.GetSessionUser(t.Context(), token)
				assert.True(t, ok, "session for %q should remain valid", username)
			}

			// verify expected invalid sessions
			for _, username := range tt.expectInvalid {
				token := tokensByUser[username]
				_, ok := svc.GetSessionUser(t.Context(), token)
				assert.False(t, ok, "session for %q should be invalidated", username)
			}
		})
	}
}

func TestService_Reload_DeleteSessionsByUsernameError(t *testing.T) {
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

	svc, err := New(f, time.Hour, false, mockStore, nil)
	require.NoError(t, err)

	// update config to trigger session invalidation for both users
	err = os.WriteFile(f, []byte(updatedConfig), 0o600)
	require.NoError(t, err)

	// reload should succeed despite DeleteSessionsByUsername error
	err = svc.Reload(t.Context())
	require.NoError(t, err, "reload should succeed even when session deletion fails")

	// verify both users were attempted (alice: password changed, bob: removed)
	assert.ElementsMatch(t, []string{"alice", "bob"}, deletedUsers,
		"should attempt to delete sessions for both changed users")

	// verify config was updated despite error
	assert.False(t, svc.CheckUserPermission("bob", "test", false),
		"bob should be removed from config")
	assert.True(t, svc.CheckUserPermission("alice", "test", false),
		"alice should still exist in config")
}

func TestService_ConcurrentAccess(t *testing.T) {
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
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	// run concurrent reads and reloads
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			_ = svc.Reload(t.Context())
		}
	}()

	// concurrent reads while reloading
	for range 1000 {
		_ = svc.Enabled()
		_ = svc.hasTokenACL("apitoken")
		_ = svc.CheckUserPermission("admin", "test", false)
		_ = svc.FilterUserKeys("admin", []string{"a", "b", "c"})
		_ = svc.filterTokenKeys("apitoken", []string{"a", "b", "c"})
		_ = svc.UserCanWrite("admin")
	}

	<-done
}

func TestService_startWatcher(t *testing.T) {
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
	svc, err := New(f, time.Hour, true, testSessionStore(t), nil)
	require.NoError(t, err)

	err = svc.startWatcher(t.Context())
	require.NoError(t, err)

	// verify initial config
	assert.True(t, svc.hasTokenACL("token1"))
	assert.False(t, svc.hasTokenACL("token2"))

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
		return svc.hasTokenACL("token2")
	}, 2*time.Second, 10*time.Millisecond, "new token should exist after reload")

	// verify old token is gone
	assert.False(t, svc.hasTokenACL("token1"), "old token should be gone")
}

func TestService_startWatcher_AtomicRename(t *testing.T) {
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

	svc, err := New(authFile, time.Hour, true, testSessionStore(t), nil)
	require.NoError(t, err)

	err = svc.startWatcher(t.Context())
	require.NoError(t, err)

	// verify initial config
	assert.True(t, svc.CheckUserPermission("admin", "test", true))
	assert.False(t, svc.CheckUserPermission("newuser", "test", false))

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
		return svc.CheckUserPermission("newuser", "test", false)
	}, 2*time.Second, 10*time.Millisecond, "new user should exist after rename")
}

func TestService_startWatcher_ContextCancel(t *testing.T) {
	config := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, config)
	svc, err := New(f, time.Hour, true, testSessionStore(t), nil)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	err = svc.startWatcher(ctx)
	require.NoError(t, err)

	// verify initial state - no "newuser"
	assert.False(t, svc.CheckUserPermission("newuser", "test", false), "newuser should not exist initially")

	// cancel the context to stop watcher
	cancel()

	// give the goroutine time to process cancellation
	time.Sleep(50 * time.Millisecond)

	// write a config change that would add newuser
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
	err = os.WriteFile(f, []byte(newConfig), 0o600)
	require.NoError(t, err)

	// wait a bit for any potential reload (should not happen)
	time.Sleep(150 * time.Millisecond)

	// verify newuser was NOT loaded (watcher was stopped)
	assert.False(t, svc.CheckUserPermission("newuser", "test", false),
		"newuser should not exist - watcher should be stopped after context cancel")
}

func TestService_startWatcher_NilService(t *testing.T) {
	var svc *Service
	err := svc.startWatcher(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth not enabled")
}

func TestService_startWatcher_EmptyAuthFile(t *testing.T) {
	svc := &Service{
		authFile:     "",
		hotReload:    true,
		users:        make(map[string]User),
		tokens:       make(map[string]TokenACL),
		sessionStore: testSessionStore(t),
	}
	err := svc.startWatcher(t.Context())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "auth file path not set")
}

func TestService_startCleanup(t *testing.T) {
	t.Run("cleanup stops on context cancel", func(t *testing.T) {
		ss := testSessionStore(t)
		svc := &Service{
			users:           make(map[string]User),
			tokens:          make(map[string]TokenACL),
			sessionStore:    ss,
			cleanupInterval: 50 * time.Millisecond,
		}

		ctx, cancel := context.WithCancel(context.Background())
		svc.startCleanup(ctx)

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
		svc := &Service{
			users:           make(map[string]User),
			tokens:          make(map[string]TokenACL),
			sessionStore:    ss,
			cleanupInterval: 50 * time.Millisecond,
		}

		cleanupCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		svc.startCleanup(cleanupCtx)

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

	t.Run("nil service is noop", func(t *testing.T) {
		var svc *Service
		svc.startCleanup(context.Background()) // should not panic
	})
}

func TestService_FilterKeysForRequest(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
  - name: reader
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "public/*"
        access: r
tokens:
  - token: "full-access-token"
    permissions:
      - prefix: "*"
        access: rw
  - token: "limited-token"
    permissions:
      - prefix: "api/*"
        access: r
  - token: "*"
    permissions:
      - prefix: "public/*"
        access: r
`
	f := createTempFile(t, content)
	ss := testSessionStore(t)
	svc, err := New(f, time.Hour, false, ss, nil)
	require.NoError(t, err)

	// note: secrets paths are excluded from wildcard access (require explicit grant)
	keys := []string{"public/key1", "private/key2", "api/config"}

	t.Run("with token - full access", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.Header.Set("X-Auth-Token", "full-access-token")
		filtered := svc.FilterKeysForRequest(req, keys)
		assert.ElementsMatch(t, keys, filtered)
	})

	t.Run("with token - limited access", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.Header.Set("X-Auth-Token", "limited-token")
		filtered := svc.FilterKeysForRequest(req, keys)
		assert.Equal(t, []string{"api/config"}, filtered)
	})

	t.Run("with session - full access", func(t *testing.T) {
		token, err := svc.CreateSession(t.Context(), "admin")
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: token})
		filtered := svc.FilterKeysForRequest(req, keys)
		assert.ElementsMatch(t, keys, filtered)
	})

	t.Run("with session - limited access", func(t *testing.T) {
		token, err := svc.CreateSession(t.Context(), "reader")
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: token})
		filtered := svc.FilterKeysForRequest(req, keys)
		assert.Equal(t, []string{"public/key1"}, filtered)
	})

	t.Run("public access", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		filtered := svc.FilterKeysForRequest(req, keys)
		assert.Equal(t, []string{"public/key1"}, filtered)
	})

	t.Run("nil service returns all keys", func(t *testing.T) {
		var nilSvc *Service
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		filtered := nilSvc.FilterKeysForRequest(req, keys)
		assert.ElementsMatch(t, keys, filtered)
	})

	t.Run("invalid token falls back to public", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.Header.Set("X-Auth-Token", "invalid-token")
		filtered := svc.FilterKeysForRequest(req, keys)
		assert.Equal(t, []string{"public/key1"}, filtered)
	})
}

func TestService_IsRequestAdmin(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    admin: true
    permissions:
      - prefix: "*"
        access: rw
  - name: regular
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: "admin-token"
    admin: true
    permissions:
      - prefix: "*"
        access: rw
  - token: "regular-token"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	ss := testSessionStore(t)
	svc, err := New(f, time.Hour, false, ss, nil)
	require.NoError(t, err)

	t.Run("admin token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/audit/query", http.NoBody)
		req.Header.Set("X-Auth-Token", "admin-token")
		assert.True(t, svc.IsRequestAdmin(req))
	})

	t.Run("non-admin token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/audit/query", http.NoBody)
		req.Header.Set("X-Auth-Token", "regular-token")
		assert.False(t, svc.IsRequestAdmin(req))
	})

	t.Run("admin user session", func(t *testing.T) {
		token, err := svc.CreateSession(t.Context(), "admin")
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, "/audit/query", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: token})
		assert.True(t, svc.IsRequestAdmin(req))
	})

	t.Run("non-admin user session", func(t *testing.T) {
		token, err := svc.CreateSession(t.Context(), "regular")
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, "/audit/query", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: token})
		assert.False(t, svc.IsRequestAdmin(req))
	})

	t.Run("no auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/audit/query", http.NoBody)
		assert.False(t, svc.IsRequestAdmin(req))
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/audit/query", http.NoBody)
		req.Header.Set("X-Auth-Token", "invalid-token")
		assert.False(t, svc.IsRequestAdmin(req))
	})

	t.Run("nil service", func(t *testing.T) {
		var nilSvc *Service
		req := httptest.NewRequest(http.MethodGet, "/audit/query", http.NoBody)
		assert.False(t, nilSvc.IsRequestAdmin(req))
	})
}

func TestService_GetRequestActor(t *testing.T) {
	content := `
users:
  - name: testuser
    password: "$2a$10$mYptn.gre3pNHlkiErjUkuCqVZgkOjWmSG5JzlKqPESw/TU5dtGB6"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: "api-token-12345678"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	ss := testSessionStore(t)
	svc, err := New(f, time.Hour, false, ss, nil)
	require.NoError(t, err)

	t.Run("with token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.Header.Set("X-Auth-Token", "api-token-12345678")
		actorType, actorName := svc.GetRequestActor(req)
		assert.Equal(t, "token", actorType)
		assert.Equal(t, "token:api-****", actorName) // first 4 chars + asterisks (MaskToken format)
	})

	t.Run("with short token", func(t *testing.T) {
		content := `
users: []
tokens:
  - token: "abc123"
    permissions:
      - prefix: "*"
        access: rw
`
		f := createTempFile(t, content)
		shortSvc, err := New(f, time.Hour, false, testSessionStore(t), nil)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.Header.Set("X-Auth-Token", "abc123")
		actorType, actorName := shortSvc.GetRequestActor(req)
		assert.Equal(t, "token", actorType)
		assert.Equal(t, "token:abc1****", actorName) // first 4 chars + asterisks (MaskToken format)
	})

	t.Run("with session", func(t *testing.T) {
		token, err := svc.CreateSession(t.Context(), "testuser")
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: token})
		actorType, actorName := svc.GetRequestActor(req)
		assert.Equal(t, "user", actorType)
		assert.Equal(t, "testuser", actorName)
	})

	t.Run("public", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		actorType, actorName := svc.GetRequestActor(req)
		assert.Equal(t, "public", actorType)
		assert.Empty(t, actorName)
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		req.Header.Set("X-Auth-Token", "invalid-token")
		actorType, actorName := svc.GetRequestActor(req)
		assert.Equal(t, "public", actorType)
		assert.Empty(t, actorName)
	})

	t.Run("nil service", func(t *testing.T) {
		var nilSvc *Service
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		actorType, actorName := nilSvc.GetRequestActor(req)
		assert.Equal(t, "public", actorType)
		assert.Empty(t, actorName)
	})
}
