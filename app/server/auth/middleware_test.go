package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestService_SessionMiddleware(t *testing.T) {
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

	middleware := svc.SessionMiddleware("/login")
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
	token, err := svc.CreateSession(t.Context(), "admin")
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

func TestService_TokenMiddleware(t *testing.T) {
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
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	handler := svc.TokenMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

	// with valid X-Auth-Token should pass
	req = httptest.NewRequest("GET", "/kv/test", http.NoBody)
	req.Header.Set("X-Auth-Token", "apitoken")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// with invalid X-Auth-Token should return 401
	req = httptest.NewRequest("GET", "/kv/test", http.NoBody)
	req.Header.Set("X-Auth-Token", "invalid")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// with invalid token should return 401
	req = httptest.NewRequest("GET", "/kv/test", http.NoBody)
	req.Header.Set("Authorization", "Bearer invalid")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// session cookie should also work for API
	token, err := svc.CreateSession(t.Context(), "admin")
	require.NoError(t, err)

	req = httptest.NewRequest("GET", "/kv/test", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "stash-auth", Value: token})
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestService_TokenMiddleware_Permissions(t *testing.T) {
	content := `
tokens:
  - token: "readonly"
    permissions:
      - prefix: "*"
        access: r
`
	f := createTempFile(t, content)
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	handler := svc.TokenMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestService_TokenMiddleware_KeyNormalization(t *testing.T) {
	// ACL for "foo_bar" should match requests for "/kv/foo bar", "/kv/foo_bar/", etc.
	content := `
tokens:
  - token: "testtoken"
    permissions:
      - prefix: "foo_bar"
        access: rw
`
	f := createTempFile(t, content)
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	handler := svc.TokenMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestTokenMiddleware_SessionCookieEnforcesACL(t *testing.T) {
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
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	handler := svc.TokenMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// create session for read-only user
	sessionToken, err := svc.CreateSession(t.Context(), "readonly")
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
	scopedSession, err := svc.CreateSession(t.Context(), "scoped")
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

func TestTokenMiddleware_PublicAccess(t *testing.T) {
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
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)
	require.True(t, svc.Enabled(), "auth should be enabled with public ACL")

	handler := svc.TokenMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestTokenMiddleware_PublicAccessWithWritePermission(t *testing.T) {
	content := `
tokens:
  - token: "*"
    permissions:
      - prefix: "writable/*"
        access: rw
`
	f := createTempFile(t, content)
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	handler := svc.TokenMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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

func TestTokenMiddleware_ListOperations(t *testing.T) {
	content := `
users:
  - name: admin
    password: "$2a$10$hash"
    permissions:
      - prefix: "*"
        access: rw
tokens:
  - token: "*"
    permissions:
      - prefix: "public/*"
        access: r
  - token: "apitoken"
    permissions:
      - prefix: "*"
        access: rw
`
	f := createTempFile(t, content)
	svc, err := New(f, time.Hour, false, testSessionStore(t), nil)
	require.NoError(t, err)

	handler := svc.TokenMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("list with public ACL passes through", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/kv/", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "public ACL should allow list pass-through")
	})

	t.Run("list with session cookie passes through", func(t *testing.T) {
		sessionToken, err := svc.CreateSession(t.Context(), "admin")
		require.NoError(t, err)

		req := httptest.NewRequest("GET", "/kv/", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: sessionToken})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "session cookie should allow list pass-through")
	})

	t.Run("list with valid token passes through", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/kv/", http.NoBody)
		req.Header.Set("Authorization", "Bearer apitoken")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "valid token should allow list pass-through")
	})
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
			assert.Equal(t, tt.want, MaskToken(tt.token))
		})
	}
}

func TestExtractToken(t *testing.T) {
	t.Run("empty request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		assert.Empty(t, ExtractToken(req))
	})

	t.Run("only X-Auth-Token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		req.Header.Set("X-Auth-Token", "xauth-value")
		assert.Equal(t, "xauth-value", ExtractToken(req))
	})

	t.Run("only Bearer token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		req.Header.Set("Authorization", "Bearer bearer-value")
		assert.Equal(t, "bearer-value", ExtractToken(req))
	})

	t.Run("both headers present", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		req.Header.Set("X-Auth-Token", "xauth-wins")
		req.Header.Set("Authorization", "Bearer bearer-loses")
		assert.Equal(t, "xauth-wins", ExtractToken(req), "X-Auth-Token should take precedence")
	})

	t.Run("malformed Authorization header", func(t *testing.T) {
		// no space after Bearer
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		req.Header.Set("Authorization", "Bearertoken")
		assert.Empty(t, ExtractToken(req))

		// wrong prefix
		req = httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
		assert.Empty(t, ExtractToken(req))
	})
}
