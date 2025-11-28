package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/web/mocks"
)

func TestHandler_HandleLoginForm(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/login", http.NoBody)
	rec := httptest.NewRecorder()
	h.handleLoginForm(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Login")
}

func TestHandler_HandleLogin(t *testing.T) {
	t.Run("valid credentials redirects", func(t *testing.T) {
		auth := &mocks.AuthProviderMock{
			IsValidUserFunc:   func(username, password string) bool { return username == "admin" && password == "testpass" },
			CreateSessionFunc: func(username string) (string, error) { return "session-token", nil },
			LoginTTLFunc:      func() time.Duration { return 24 * time.Hour },
		}
		h := newTestHandlerWithAuth(t, auth)

		req := httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"username": {"admin"}, "password": {"testpass"}}
		rec := httptest.NewRecorder()
		h.handleLogin(rec, req)

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
		auth := &mocks.AuthProviderMock{
			IsValidUserFunc: func(username, password string) bool { return false },
		}
		h := newTestHandlerWithAuth(t, auth)

		req := httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"username": {"admin"}, "password": {"wrongpass"}}
		rec := httptest.NewRecorder()
		h.handleLogin(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "Invalid username or password")
	})

	t.Run("empty credentials shows error", func(t *testing.T) {
		h := newTestHandler(t)

		req := httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"username": {""}, "password": {""}}
		rec := httptest.NewRecorder()
		h.handleLogin(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "Username and password are required")
	})
}

func TestHandler_HandleLogout(t *testing.T) {
	invalidateCalled := false
	auth := &mocks.AuthProviderMock{
		InvalidateSessionFunc: func(token string) { invalidateCalled = true },
	}
	h := newTestHandlerWithAuth(t, auth)

	req := httptest.NewRequest(http.MethodPost, "/logout", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "somesession"})
	rec := httptest.NewRecorder()
	h.handleLogout(rec, req)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login", rec.Header().Get("Location"))
	assert.True(t, invalidateCalled)
	// should clear cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "stash-auth" {
			assert.Equal(t, -1, c.MaxAge)
		}
	}
}

func TestHandler_RenderLoginError(t *testing.T) {
	h := newTestHandler(t)

	req := httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
	rec := httptest.NewRecorder()
	h.renderLoginError(rec, req, "Test error message")

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "Test error message")
}

// newTestHandlerWithStore creates a test handler with a custom store.
func newTestHandlerWithStore(t *testing.T, st KVStore) *Handler {
	t.Helper()
	auth := &mocks.AuthProviderMock{
		EnabledFunc:             func() bool { return false },
		GetSessionUserFunc:      func(token string) (string, bool) { return "", false },
		FilterUserKeysFunc:      func(username string, keys []string) []string { return keys },
		CheckUserPermissionFunc: func(username, key string, write bool) bool { return true },
		UserCanWriteFunc:        func(username string) bool { return true },
	}
	h, err := New(st, auth, defaultValidatorMock(), nil, Config{})
	require.NoError(t, err)
	return h
}
