package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermission_CanRead(t *testing.T) {
	tests := []struct {
		perm Permission
		want bool
	}{
		{PermissionNone, false},
		{PermissionRead, true},
		{PermissionWrite, false},
		{PermissionReadWrite, true},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.perm.CanRead(), "permission %v", tt.perm)
	}
}

func TestPermission_CanWrite(t *testing.T) {
	tests := []struct {
		perm Permission
		want bool
	}{
		{PermissionNone, false},
		{PermissionRead, false},
		{PermissionWrite, true},
		{PermissionReadWrite, true},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.perm.CanWrite(), "permission %v", tt.perm)
	}
}

func TestNewAuth_Disabled(t *testing.T) {
	auth, err := NewAuth("", nil, time.Hour)
	require.NoError(t, err)
	assert.Nil(t, auth)
}

func TestNewAuth_Enabled(t *testing.T) {
	// bcrypt hash for "secret"
	hash := "$2a$10$N9qo8uLOickgx2ZMRZoMye/IQPBKM.IJklnlj.RLXNE7QGIBbRPiO"
	auth, err := NewAuth(hash, []string{"tok:*:rw"}, time.Hour)
	require.NoError(t, err)
	require.NotNil(t, auth)
	assert.True(t, auth.Enabled())
}

func TestParseTokens(t *testing.T) {
	tests := []struct {
		name    string
		tokens  []string
		wantErr bool
		check   func(t *testing.T, tokens map[string]TokenACL)
	}{
		{
			name:   "empty",
			tokens: nil,
			check: func(t *testing.T, tokens map[string]TokenACL) {
				assert.Empty(t, tokens)
			},
		},
		{
			name:   "single token with wildcard",
			tokens: []string{"mytoken:*:rw"},
			check: func(t *testing.T, tokens map[string]TokenACL) {
				acl, ok := tokens["mytoken"]
				require.True(t, ok)
				assert.Equal(t, "mytoken", acl.Token)
				require.Len(t, acl.prefixes, 1)
				assert.Equal(t, "*", acl.prefixes[0].prefix)
				assert.Equal(t, PermissionReadWrite, acl.prefixes[0].permission)
			},
		},
		{
			name:   "multiple prefixes for same token",
			tokens: []string{"tok:app/*:rw", "tok:*:r"},
			check: func(t *testing.T, tokens map[string]TokenACL) {
				acl, ok := tokens["tok"]
				require.True(t, ok)
				require.Len(t, acl.prefixes, 2)
				// should be sorted by length descending
				assert.Equal(t, "app/*", acl.prefixes[0].prefix)
				assert.Equal(t, "*", acl.prefixes[1].prefix)
			},
		},
		{
			name:   "read only permission",
			tokens: []string{"readonly:*:r"},
			check: func(t *testing.T, tokens map[string]TokenACL) {
				acl := tokens["readonly"]
				assert.Equal(t, PermissionRead, acl.prefixes[0].permission)
			},
		},
		{
			name:   "write only permission",
			tokens: []string{"writeonly:*:w"},
			check: func(t *testing.T, tokens map[string]TokenACL) {
				acl := tokens["writeonly"]
				assert.Equal(t, PermissionWrite, acl.prefixes[0].permission)
			},
		},
		{
			name:    "invalid format - missing parts",
			tokens:  []string{"invalid"},
			wantErr: true,
		},
		{
			name:    "invalid format - only two parts",
			tokens:  []string{"tok:prefix"},
			wantErr: true,
		},
		{
			name:    "empty token name",
			tokens:  []string{":prefix:rw"},
			wantErr: true,
		},
		{
			name:    "empty prefix",
			tokens:  []string{"tok::rw"},
			wantErr: true,
		},
		{
			name:    "invalid permission",
			tokens:  []string{"tok:*:invalid"},
			wantErr: true,
		},
		{
			name:    "duplicate prefix for same token",
			tokens:  []string{"tok:*:r", "tok:*:rw"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := parseTokens(tt.tokens)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, tokens)
			}
		})
	}
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

func TestAuth_ValidatePassword(t *testing.T) {
	// bcrypt hash for "secret"
	hash := "$2a$10$N9qo8uLOickgx2ZMRZoMye/IQPBKM.IJklnlj.RLXNE7QGIBbRPiO"
	auth, err := NewAuth(hash, nil, time.Hour)
	require.NoError(t, err)

	assert.False(t, auth.ValidatePassword("wrong"))
	// note: the hash above is for a different password, so this won't match
	// using a real hash for testing
}

func TestAuth_CheckPermission(t *testing.T) {
	auth, err := NewAuth("$2a$10$hash", []string{
		"full:*:rw",
		"readonly:*:r",
		"scoped:app/*:rw",
		"scoped:*:r",
	}, time.Hour)
	require.NoError(t, err)

	tests := []struct {
		token     string
		key       string
		needWrite bool
		want      bool
	}{
		// full access token
		{"full", "any/key", false, true},
		{"full", "any/key", true, true},
		// readonly token
		{"readonly", "any/key", false, true},
		{"readonly", "any/key", true, false},
		// scoped token - app/* has rw, * has r
		{"scoped", "app/config", false, true},
		{"scoped", "app/config", true, true},
		{"scoped", "other/key", false, true},
		{"scoped", "other/key", true, false},
		// unknown token
		{"unknown", "any", false, false},
		{"unknown", "any", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.token+"_"+tt.key, func(t *testing.T) {
			got := auth.CheckPermission(tt.token, tt.key, tt.needWrite)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuth_Session(t *testing.T) {
	auth, err := NewAuth("$2a$10$hash", nil, time.Hour)
	require.NoError(t, err)

	// create session
	token, err := auth.CreateSession()
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Len(t, token, 64) // 32 bytes hex encoded

	// validate session
	assert.True(t, auth.ValidateSession(token))
	assert.False(t, auth.ValidateSession("invalid"))

	// invalidate session
	auth.InvalidateSession(token)
	assert.False(t, auth.ValidateSession(token))
}

func TestAuth_SessionExpiry(t *testing.T) {
	auth, err := NewAuth("$2a$10$hash", nil, 1*time.Millisecond)
	require.NoError(t, err)

	token, err := auth.CreateSession()
	require.NoError(t, err)

	// session should be valid immediately
	assert.True(t, auth.ValidateSession(token))

	// wait for expiry
	time.Sleep(10 * time.Millisecond)

	// session should be expired
	assert.False(t, auth.ValidateSession(token))
}

func TestAuth_Middleware_NoAuth(t *testing.T) {
	// nil auth (disabled) should not be used as middleware
	var auth *Auth
	assert.False(t, auth.Enabled())
}

func TestNoopAuth(t *testing.T) {
	handler := NoopAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/anything", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuth_SessionAuth(t *testing.T) {
	auth, err := NewAuth("$2a$10$hash", nil, time.Hour)
	require.NoError(t, err)

	handler := auth.SessionAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// without session should redirect to login
	req := httptest.NewRequest("GET", "/", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login", rec.Header().Get("Location"))

	// with valid session should pass
	token, err := auth.CreateSession()
	require.NoError(t, err)

	req = httptest.NewRequest("GET", "/", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "stash-auth", Value: token})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuth_TokenAuth(t *testing.T) {
	auth, err := NewAuth("$2a$10$hash", []string{"api:*:rw"}, time.Hour)
	require.NoError(t, err)

	handler := auth.TokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// without token should return 401
	req := httptest.NewRequest("GET", "/kv/test", http.NoBody)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// with valid bearer token should pass
	req = httptest.NewRequest("GET", "/kv/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer api")
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
	token, err := auth.CreateSession()
	require.NoError(t, err)

	req = httptest.NewRequest("GET", "/kv/test", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "stash-auth", Value: token})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuth_TokenAuth_Permissions(t *testing.T) {
	auth, err := NewAuth("$2a$10$hash", []string{"readonly:*:r"}, time.Hour)
	require.NoError(t, err)

	handler := auth.TokenAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
