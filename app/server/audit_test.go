package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/server/mocks"
	"github.com/umputun/stash/app/store"
)

func TestResponseCapture(t *testing.T) {
	t.Run("captures status and bytes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rc := newResponseCapture(rec)

		rc.WriteHeader(http.StatusCreated)
		n, err := rc.Write([]byte("hello world"))

		require.NoError(t, err)
		assert.Equal(t, 11, n)
		assert.Equal(t, http.StatusCreated, rc.status)
		assert.Equal(t, 11, rc.bytesWritten)
		assert.Equal(t, "hello world", rec.Body.String())
	})

	t.Run("default status is 200", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rc := newResponseCapture(rec)

		_, _ = rc.Write([]byte("test"))

		assert.Equal(t, http.StatusOK, rc.status)
	})

	t.Run("unwrap returns underlying writer", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rc := newResponseCapture(rec)

		assert.Equal(t, rec, rc.Unwrap())
	})
}

func TestAuditMiddleware(t *testing.T) {
	t.Run("logs audit entry for kv GET", func(t *testing.T) {
		var capturedEntry store.AuditEntry
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, token string) (string, bool) {
				if token != "" {
					return "testuser", true
				}
				return "", false
			},
			HasTokenACLFunc: func(_ string) bool { return false },
			IsAdminFunc:     func(_ string) bool { return false },
		}
		middleware := AuditMiddleware(auditStore, auth)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("value data"))
		}))

		req := httptest.NewRequest(http.MethodGet, "/kv/app/config", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "test-session"})
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Len(t, auditStore.LogAuditCalls(), 1)
		assert.Equal(t, "app/config", capturedEntry.Key)
		assert.Equal(t, enum.AuditActionRead, capturedEntry.Action)
		assert.Equal(t, enum.AuditResultSuccess, capturedEntry.Result)
		assert.Equal(t, "testuser", capturedEntry.Actor)
		assert.Equal(t, enum.ActorTypeUser, capturedEntry.ActorType)
		require.NotNil(t, capturedEntry.ValueSize)
		assert.Equal(t, 10, *capturedEntry.ValueSize)
	})

	t.Run("logs audit entry for kv PUT", func(t *testing.T) {
		var capturedEntry store.AuditEntry
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "", false },
			HasTokenACLFunc:    func(token string) bool { return token == "mytoken12345" },
			IsAdminFunc:        func(_ string) bool { return false },
		}
		middleware := AuditMiddleware(auditStore, auth)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPut, "/kv/app/config", http.NoBody)
		req.Header.Set("Authorization", "Bearer mytoken12345")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Len(t, auditStore.LogAuditCalls(), 1)
		assert.Equal(t, "app/config", capturedEntry.Key)
		assert.Equal(t, enum.AuditActionUpdate, capturedEntry.Action)
		assert.Equal(t, enum.AuditResultSuccess, capturedEntry.Result)
		assert.Equal(t, "token:myto****", capturedEntry.Actor)
		assert.Equal(t, enum.ActorTypeToken, capturedEntry.ActorType)
	})

	t.Run("logs audit entry for kv DELETE", func(t *testing.T) {
		var capturedEntry store.AuditEntry
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := AuditMiddleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))

		req := httptest.NewRequest(http.MethodDelete, "/kv/app/config", http.NoBody)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Len(t, auditStore.LogAuditCalls(), 1)
		assert.Equal(t, enum.AuditActionDelete, capturedEntry.Action)
		assert.Equal(t, enum.AuditResultSuccess, capturedEntry.Result)
		assert.Equal(t, "anonymous", capturedEntry.Actor)
		assert.Equal(t, enum.ActorTypePublic, capturedEntry.ActorType)
		assert.Nil(t, capturedEntry.ValueSize) // no size for delete
	})

	t.Run("logs denied result for 403", func(t *testing.T) {
		var capturedEntry store.AuditEntry
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := AuditMiddleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))

		req := httptest.NewRequest(http.MethodGet, "/kv/secret/key", http.NoBody)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, enum.AuditResultDenied, capturedEntry.Result)
		assert.Nil(t, capturedEntry.ValueSize) // no size for denied
	})

	t.Run("logs denied result for 401", func(t *testing.T) {
		var capturedEntry store.AuditEntry
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := AuditMiddleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))

		req := httptest.NewRequest(http.MethodGet, "/kv/protected/key", http.NoBody)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, enum.AuditResultDenied, capturedEntry.Result)
		assert.Nil(t, capturedEntry.ValueSize)
	})

	t.Run("captures denial when auth middleware short-circuits", func(t *testing.T) {
		// this tests the middleware ordering: audit runs BEFORE auth,
		// so even when auth rejects and doesn't call next, audit still logs the denial
		var capturedEntry store.AuditEntry
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		// auth middleware that rejects without calling next
		authMiddleware := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
				// note: does NOT call next.ServeHTTP - simulates auth rejection
			})
		}

		// handler that should never be called
		handlerCalled := false
		finalHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		// chain: audit → auth → handler (same order as server.go)
		auditMiddleware := AuditMiddleware(auditStore, nil)
		chain := auditMiddleware(authMiddleware(finalHandler))

		req := httptest.NewRequest(http.MethodGet, "/kv/secret/data", http.NoBody)
		rec := httptest.NewRecorder()

		chain.ServeHTTP(rec, req)

		assert.False(t, handlerCalled, "handler should not be called when auth rejects")
		assert.Equal(t, http.StatusForbidden, rec.Code)
		require.Len(t, auditStore.LogAuditCalls(), 1, "audit should log even when auth rejects")
		assert.Equal(t, "secret/data", capturedEntry.Key)
		assert.Equal(t, enum.AuditActionRead, capturedEntry.Action)
		assert.Equal(t, enum.AuditResultDenied, capturedEntry.Result)
		assert.Nil(t, capturedEntry.ValueSize)
	})

	t.Run("logs not_found result for 404", func(t *testing.T) {
		var capturedEntry store.AuditEntry
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := AuditMiddleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

		req := httptest.NewRequest(http.MethodGet, "/kv/missing/key", http.NoBody)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, enum.AuditResultNotFound, capturedEntry.Result)
	})

	t.Run("skips list operation", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, _ store.AuditEntry) error { return nil },
		}

		middleware := AuditMiddleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// GET /kv/ is list operation
		req := httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Empty(t, auditStore.LogAuditCalls())

		// GET /kv is also list operation
		req = httptest.NewRequest(http.MethodGet, "/kv", http.NoBody)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Empty(t, auditStore.LogAuditCalls())
	})

	t.Run("skips non-kv routes", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, _ store.AuditEntry) error { return nil },
		}

		middleware := AuditMiddleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/web/keys", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Empty(t, auditStore.LogAuditCalls())
	})

	t.Run("captures request metadata", func(t *testing.T) {
		var capturedEntry store.AuditEntry
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := AuditMiddleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)
		req.Header.Set("User-Agent", "test-agent/1.0")
		req.Header.Set("X-Request-ID", "req-123")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Equal(t, "test-agent/1.0", capturedEntry.UserAgent)
		assert.Equal(t, "req-123", capturedEntry.RequestID)
	})
}

func TestNoopAuditMiddleware(t *testing.T) {
	called := false
	handler := NoopAuditMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestAuditor_MapAction(t *testing.T) {
	aud := newAuditor(nil, nil)
	tests := []struct {
		name   string
		method string
		status int
		want   enum.AuditAction
	}{
		{"GET 200", http.MethodGet, 200, enum.AuditActionRead},
		{"PUT 201 creates", http.MethodPut, 201, enum.AuditActionCreate},
		{"PUT 200 updates", http.MethodPut, 200, enum.AuditActionUpdate},
		{"DELETE", http.MethodDelete, 204, enum.AuditActionDelete},
		{"POST fallback", http.MethodPost, 200, enum.AuditActionRead},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := aud.mapAction(tt.method, tt.status)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuditor_MapStatus(t *testing.T) {
	aud := newAuditor(nil, nil)
	tests := []struct {
		status int
		want   enum.AuditResult
	}{
		{200, enum.AuditResultSuccess},
		{201, enum.AuditResultSuccess},
		{204, enum.AuditResultSuccess},
		{403, enum.AuditResultDenied},
		{401, enum.AuditResultDenied},
		{404, enum.AuditResultNotFound},
		{400, enum.AuditResultNotFound}, // other errors
		{500, enum.AuditResultNotFound},
	}

	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			got := aud.mapStatus(tt.status)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuditor_ExtractActor(t *testing.T) {
	t.Run("nil auth returns anonymous", func(t *testing.T) {
		aud := newAuditor(nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)
		actor, actorType := aud.extractActor(req)
		assert.Equal(t, "anonymous", actor)
		assert.Equal(t, enum.ActorTypePublic, actorType)
	})

	t.Run("session cookie user", func(t *testing.T) {
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, token string) (string, bool) {
				if token == "valid-session" {
					return "alice", true
				}
				return "", false
			},
			HasTokenACLFunc: func(_ string) bool { return false },
			IsAdminFunc:     func(_ string) bool { return false },
		}
		aud := newAuditor(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "valid-session"})

		actor, actorType := aud.extractActor(req)

		assert.Equal(t, "alice", actor)
		assert.Equal(t, enum.ActorTypeUser, actorType)
	})

	t.Run("bearer token", func(t *testing.T) {
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "", false },
			HasTokenACLFunc:    func(token string) bool { return token == "abcdefghij12345" },
			IsAdminFunc:        func(_ string) bool { return false },
		}
		aud := newAuditor(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)
		req.Header.Set("Authorization", "Bearer abcdefghij12345")

		actor, actorType := aud.extractActor(req)

		assert.Equal(t, "token:abcd****", actor)
		assert.Equal(t, enum.ActorTypeToken, actorType)
	})

	t.Run("short token masked with stars", func(t *testing.T) {
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "", false },
			HasTokenACLFunc:    func(token string) bool { return token == "short" },
			IsAdminFunc:        func(_ string) bool { return false },
		}
		aud := newAuditor(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)
		req.Header.Set("Authorization", "Bearer short")

		actor, actorType := aud.extractActor(req)

		assert.Equal(t, "token:shor****", actor)
		assert.Equal(t, enum.ActorTypeToken, actorType)
	})

	t.Run("very short token fully masked", func(t *testing.T) {
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "", false },
			HasTokenACLFunc:    func(token string) bool { return token == "abc" },
			IsAdminFunc:        func(_ string) bool { return false },
		}
		aud := newAuditor(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)
		req.Header.Set("Authorization", "Bearer abc")

		actor, actorType := aud.extractActor(req)

		assert.Equal(t, "token:****", actor)
		assert.Equal(t, enum.ActorTypeToken, actorType)
	})

	t.Run("invalid session falls back to token", func(t *testing.T) {
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "", false },
			HasTokenACLFunc:    func(token string) bool { return token == "mytoken123456" },
			IsAdminFunc:        func(_ string) bool { return false },
		}
		aud := newAuditor(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "invalid"})
		req.Header.Set("Authorization", "Bearer mytoken123456")

		actor, actorType := aud.extractActor(req)

		assert.Equal(t, "token:myto****", actor)
		assert.Equal(t, enum.ActorTypeToken, actorType)
	})

	t.Run("no auth returns anonymous", func(t *testing.T) {
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "", false },
			HasTokenACLFunc:    func(_ string) bool { return false },
			IsAdminFunc:        func(_ string) bool { return false },
		}
		aud := newAuditor(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)

		actor, actorType := aud.extractActor(req)

		assert.Equal(t, "anonymous", actor)
		assert.Equal(t, enum.ActorTypePublic, actorType)
	})
}

func TestAuditHandler_HandleQuery(t *testing.T) {
	t.Run("returns unauthorized without session", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{}
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "", false },
			HasTokenACLFunc:    func(_ string) bool { return false },
			IsAdminFunc:        func(_ string) bool { return false },
		}
		handler := NewAuditHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("returns forbidden for non-admin user", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{}
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "regularuser", true },
			HasTokenACLFunc:    func(_ string) bool { return false },
			IsAdminFunc:        func(_ string) bool { return false },
		}
		handler := NewAuditHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "valid-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("queries audit log for admin user", func(t *testing.T) {
		entries := []store.AuditEntry{
			{ID: 1, Key: "test/key", Action: enum.AuditActionRead, ActorType: enum.ActorTypeUser, Result: enum.AuditResultSuccess},
		}
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return entries, 1, nil
			},
		}
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			HasTokenACLFunc:    func(_ string) bool { return false },
			IsAdminFunc:        func(username string) bool { return username == "admin" },
		}
		handler := NewAuditHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{"key":"test/*"}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, auditStore.QueryAuditCalls(), 1)
		assert.Equal(t, "test/*", auditStore.QueryAuditCalls()[0].Q.Key)

		var resp AuditQueryResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 1, resp.Total)
		assert.Len(t, resp.Entries, 1)
	})

	t.Run("applies max limit", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return nil, 0, nil
			},
		}
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			HasTokenACLFunc:    func(_ string) bool { return false },
			IsAdminFunc:        func(username string) bool { return username == "admin" },
		}
		handler := NewAuditHandler(auditStore, auth, 50) // max limit 50

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{"limit":100}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, auditStore.QueryAuditCalls(), 1)
		assert.Equal(t, 50, auditStore.QueryAuditCalls()[0].Q.Limit) // capped at 50
	})

	t.Run("parses all filter fields", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return nil, 0, nil
			},
		}
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			HasTokenACLFunc:    func(_ string) bool { return false },
			IsAdminFunc:        func(username string) bool { return username == "admin" },
		}
		handler := NewAuditHandler(auditStore, auth, 1000)

		body := `{
			"key": "app/*",
			"actor": "testuser",
			"actor_type": "user",
			"action": "read",
			"result": "success",
			"from": "2025-01-01T00:00:00Z",
			"to": "2025-12-31T23:59:59Z",
			"limit": 100
		}`
		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(body))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, auditStore.QueryAuditCalls(), 1)

		q := auditStore.QueryAuditCalls()[0].Q
		assert.Equal(t, "app/*", q.Key)
		assert.Equal(t, "testuser", q.Actor)
		assert.Equal(t, enum.ActorTypeUser, q.ActorType)
		assert.Equal(t, enum.AuditActionRead, q.Action)
		assert.Equal(t, enum.AuditResultSuccess, q.Result)
		assert.Equal(t, 100, q.Limit)
		assert.False(t, q.From.IsZero())
		assert.False(t, q.To.IsZero())
	})

	t.Run("returns error for invalid action", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{}
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			HasTokenACLFunc:    func(_ string) bool { return false },
			IsAdminFunc:        func(username string) bool { return username == "admin" },
		}
		handler := NewAuditHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{"action":"invalid"}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("returns error for invalid timestamp", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{}
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			HasTokenACLFunc:    func(_ string) bool { return false },
			IsAdminFunc:        func(username string) bool { return username == "admin" },
		}
		handler := NewAuditHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{"from":"not-a-date"}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("returns empty array for no results", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return nil, 0, nil
			},
		}
		auth := &mocks.AuditAuthMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			HasTokenACLFunc:    func(_ string) bool { return false },
			IsAdminFunc:        func(username string) bool { return username == "admin" },
		}
		handler := NewAuditHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp AuditQueryResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotNil(t, resp.Entries)
		assert.Empty(t, resp.Entries)
	})
}

func TestNewAuditHandler(t *testing.T) {
	t.Run("applies default max limit", func(t *testing.T) {
		handler := NewAuditHandler(nil, nil, 0)
		assert.Equal(t, 10000, handler.maxLimit)
	})

	t.Run("uses provided max limit", func(t *testing.T) {
		handler := NewAuditHandler(nil, nil, 500)
		assert.Equal(t, 500, handler.maxLimit)
	})
}
