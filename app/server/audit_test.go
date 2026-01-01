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
			GetRequestActorFunc: func(_ *http.Request) (string, string) {
				return "user", "testuser"
			},
			IsRequestAdminFunc: func(_ *http.Request) bool { return false },
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
			GetRequestActorFunc: func(_ *http.Request) (string, string) {
				return "token", "token:myto****"
			},
			IsRequestAdminFunc: func(_ *http.Request) bool { return false },
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
		assert.Nil(t, capturedEntry.ValueSize) // no value size for delete
	})

	t.Run("logs audit entry for kv PUT create", func(t *testing.T) {
		var capturedEntry store.AuditEntry
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := AuditMiddleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("new value"))
		}))

		req := httptest.NewRequest(http.MethodPut, "/kv/new/key", http.NoBody)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Len(t, auditStore.LogAuditCalls(), 1)
		assert.Equal(t, enum.AuditActionCreate, capturedEntry.Action)
		assert.Equal(t, enum.AuditResultSuccess, capturedEntry.Result)
		require.NotNil(t, capturedEntry.ValueSize)
		assert.Equal(t, 9, *capturedEntry.ValueSize)
	})

	t.Run("skips non-kv routes", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, _ store.AuditEntry) error {
				return nil
			},
		}

		middleware := AuditMiddleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/other/path", http.NoBody)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Empty(t, auditStore.LogAuditCalls())
	})

	t.Run("skips kv list operation", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			LogAuditFunc: func(_ context.Context, _ store.AuditEntry) error {
				return nil
			},
		}

		middleware := AuditMiddleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// test /kv
		req := httptest.NewRequest(http.MethodGet, "/kv", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Empty(t, auditStore.LogAuditCalls())

		// test /kv/
		req = httptest.NewRequest(http.MethodGet, "/kv/", http.NoBody)
		rec = httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Empty(t, auditStore.LogAuditCalls())
	})

	t.Run("logs failed requests", func(t *testing.T) {
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

		require.Len(t, auditStore.LogAuditCalls(), 1)
		assert.Equal(t, enum.AuditActionRead, capturedEntry.Action)
		assert.Equal(t, enum.AuditResultNotFound, capturedEntry.Result)
		assert.Nil(t, capturedEntry.ValueSize)
	})

	t.Run("logs forbidden requests", func(t *testing.T) {
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

		req := httptest.NewRequest(http.MethodPut, "/kv/restricted/key", http.NoBody)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Len(t, auditStore.LogAuditCalls(), 1)
		assert.Equal(t, enum.AuditActionUpdate, capturedEntry.Action)
		assert.Equal(t, enum.AuditResultDenied, capturedEntry.Result)
	})

	t.Run("normalizes key path", func(t *testing.T) {
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

		req := httptest.NewRequest(http.MethodGet, "/kv//app///config/", http.NoBody)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Len(t, auditStore.LogAuditCalls(), 1)
		assert.Equal(t, "app///config", capturedEntry.Key) // only leading/trailing slashes trimmed
	})
}

func TestAuditor_MapAction(t *testing.T) {
	aud := newAuditor(nil, nil)

	tests := []struct {
		method string
		status int
		want   enum.AuditAction
	}{
		{http.MethodGet, http.StatusOK, enum.AuditActionRead},
		{http.MethodGet, http.StatusNotFound, enum.AuditActionRead},
		{http.MethodPut, http.StatusOK, enum.AuditActionUpdate},
		{http.MethodPut, http.StatusCreated, enum.AuditActionCreate},
		{http.MethodDelete, http.StatusNoContent, enum.AuditActionDelete},
		{http.MethodPost, http.StatusOK, enum.AuditActionRead}, // fallback
	}

	for _, tt := range tests {
		name := tt.method + "_" + http.StatusText(tt.status)
		t.Run(name, func(t *testing.T) {
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
		{http.StatusOK, enum.AuditResultSuccess},
		{http.StatusCreated, enum.AuditResultSuccess},
		{http.StatusNoContent, enum.AuditResultSuccess},
		{http.StatusNotFound, enum.AuditResultNotFound},
		{http.StatusForbidden, enum.AuditResultDenied},
		{http.StatusUnauthorized, enum.AuditResultDenied},
		{http.StatusBadRequest, enum.AuditResultNotFound},
		{http.StatusInternalServerError, enum.AuditResultNotFound},
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

	t.Run("user actor", func(t *testing.T) {
		auth := &mocks.AuditAuthMock{
			GetRequestActorFunc: func(_ *http.Request) (string, string) {
				return "user", "alice"
			},
			IsRequestAdminFunc: func(_ *http.Request) bool { return false },
		}
		aud := newAuditor(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)

		actor, actorType := aud.extractActor(req)

		assert.Equal(t, "alice", actor)
		assert.Equal(t, enum.ActorTypeUser, actorType)
	})

	t.Run("token actor", func(t *testing.T) {
		auth := &mocks.AuditAuthMock{
			GetRequestActorFunc: func(_ *http.Request) (string, string) {
				return "token", "token:abcd****"
			},
			IsRequestAdminFunc: func(_ *http.Request) bool { return false },
		}
		aud := newAuditor(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)

		actor, actorType := aud.extractActor(req)

		assert.Equal(t, "token:abcd****", actor)
		assert.Equal(t, enum.ActorTypeToken, actorType)
	})

	t.Run("public actor", func(t *testing.T) {
		auth := &mocks.AuditAuthMock{
			GetRequestActorFunc: func(_ *http.Request) (string, string) {
				return "public", ""
			},
			IsRequestAdminFunc: func(_ *http.Request) bool { return false },
		}
		aud := newAuditor(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)

		actor, actorType := aud.extractActor(req)

		assert.Equal(t, "anonymous", actor)
		assert.Equal(t, enum.ActorTypePublic, actorType)
	})
}

func TestAuditHandler_HandleQuery(t *testing.T) {
	t.Run("returns unauthorized without auth", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{}
		auth := &mocks.AuditAuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return false },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "public", "" },
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
			IsRequestAdminFunc:  func(_ *http.Request) bool { return false },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "regularuser" },
		}
		handler := NewAuditHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "valid-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("returns forbidden for non-admin token", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{}
		auth := &mocks.AuditAuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return false },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "token", "token:regu****" },
		}
		handler := NewAuditHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer regulartoken")
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
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
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

	t.Run("queries audit log for admin token", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return []store.AuditEntry{}, 0, nil
			},
		}
		auth := &mocks.AuditAuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "token", "token:admi****" },
		}
		handler := NewAuditHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer admintoken123")
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, auditStore.QueryAuditCalls(), 1)
	})

	t.Run("applies max limit", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return nil, 0, nil
			},
		}
		auth := &mocks.AuditAuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
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
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
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
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
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
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
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
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
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

	t.Run("returns error for malformed JSON body", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{}
		auth := &mocks.AuditAuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
		}
		handler := NewAuditHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{invalid json`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "invalid request body")
	})

	t.Run("returns error when store query fails", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return nil, 0, assert.AnError
			},
		}
		auth := &mocks.AuditAuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
		}
		handler := NewAuditHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "failed to query audit log")
	})

	t.Run("returns unauthorized for nil auth", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{}
		handler := NewAuditHandler(auditStore, nil, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
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
