package audit

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
	"github.com/umputun/stash/app/server/audit/mocks"
	"github.com/umputun/stash/app/store"
)

func TestHandler_HandleQuery(t *testing.T) {
	t.Run("returns unauthorized without auth", func(t *testing.T) {
		auditStore := &mocks.StoreMock{}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return false },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "public", "" },
		}
		handler := NewHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("returns forbidden for non-admin user", func(t *testing.T) {
		auditStore := &mocks.StoreMock{}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return false },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "regularuser" },
		}
		handler := NewHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "valid-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("returns forbidden for non-admin token", func(t *testing.T) {
		auditStore := &mocks.StoreMock{}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return false },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "token", "token:regu****" },
		}
		handler := NewHandler(auditStore, auth, 100)

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
		auditStore := &mocks.StoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return entries, 1, nil
			},
		}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
		}
		handler := NewHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{"key":"test/*"}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, auditStore.QueryAuditCalls(), 1)
		assert.Equal(t, "test/*", auditStore.QueryAuditCalls()[0].Q.Key)

		var resp QueryResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, 1, resp.Total)
		assert.Len(t, resp.Entries, 1)
	})

	t.Run("queries audit log for admin token", func(t *testing.T) {
		auditStore := &mocks.StoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return []store.AuditEntry{}, 0, nil
			},
		}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "token", "token:admi****" },
		}
		handler := NewHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		req.Header.Set("Authorization", "Bearer admintoken123")
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, auditStore.QueryAuditCalls(), 1)
	})

	t.Run("applies max limit", func(t *testing.T) {
		auditStore := &mocks.StoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return nil, 0, nil
			},
		}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
		}
		handler := NewHandler(auditStore, auth, 50) // max limit 50

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{"limit":100}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		require.Len(t, auditStore.QueryAuditCalls(), 1)
		assert.Equal(t, 50, auditStore.QueryAuditCalls()[0].Q.Limit) // capped at 50
	})

	t.Run("parses all filter fields", func(t *testing.T) {
		auditStore := &mocks.StoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return nil, 0, nil
			},
		}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
		}
		handler := NewHandler(auditStore, auth, 1000)

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
		auditStore := &mocks.StoreMock{}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
		}
		handler := NewHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{"action":"invalid"}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("returns error for invalid timestamp", func(t *testing.T) {
		auditStore := &mocks.StoreMock{}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
		}
		handler := NewHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{"from":"not-a-date"}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("returns empty array for no results", func(t *testing.T) {
		auditStore := &mocks.StoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return nil, 0, nil
			},
		}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
		}
		handler := NewHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var resp QueryResponse
		err := json.NewDecoder(rec.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotNil(t, resp.Entries)
		assert.Empty(t, resp.Entries)
	})

	t.Run("returns error for malformed JSON body", func(t *testing.T) {
		auditStore := &mocks.StoreMock{}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
		}
		handler := NewHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{invalid json`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Contains(t, rec.Body.String(), "invalid request body")
	})

	t.Run("returns error when store query fails", func(t *testing.T) {
		auditStore := &mocks.StoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return nil, 0, assert.AnError
			},
		}
		auth := &mocks.AuthMock{
			IsRequestAdminFunc:  func(_ *http.Request) bool { return true },
			GetRequestActorFunc: func(_ *http.Request) (string, string) { return "user", "admin" },
		}
		handler := NewHandler(auditStore, auth, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "admin-session"})
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Contains(t, rec.Body.String(), "failed to query audit log")
	})

	t.Run("returns unauthorized for nil auth", func(t *testing.T) {
		auditStore := &mocks.StoreMock{}
		handler := NewHandler(auditStore, nil, 100)

		req := httptest.NewRequest(http.MethodPost, "/audit/query", strings.NewReader(`{}`))
		rec := httptest.NewRecorder()

		handler.HandleQuery(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

func TestNewHandler(t *testing.T) {
	t.Run("applies default max limit", func(t *testing.T) {
		handler := NewHandler(nil, nil, 0)
		assert.Equal(t, 10000, handler.maxLimit)
	})

	t.Run("uses provided max limit", func(t *testing.T) {
		handler := NewHandler(nil, nil, 500)
		assert.Equal(t, 500, handler.maxLimit)
	})
}
