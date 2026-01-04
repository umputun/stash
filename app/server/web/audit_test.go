package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/server/web/mocks"
	"github.com/umputun/stash/app/store"
)

func TestAuditHandler_HandleAuditPage(t *testing.T) {
	t.Run("redirects unauthenticated user to login", func(t *testing.T) {
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "", false },
		}
		h := newTestAuditHandler(t, nil, auth)

		req := httptest.NewRequest(http.MethodGet, "/audit", http.NoBody)
		rec := httptest.NewRecorder()
		h.HandleAuditPage(rec, req)

		assert.Equal(t, http.StatusFound, rec.Code)
		assert.Contains(t, rec.Header().Get("Location"), "/login")
	})

	t.Run("returns 403 for non-admin user", func(t *testing.T) {
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "user", true },
			IsAdminFunc:        func(username string) bool { return false },
		}
		h := newTestAuditHandler(t, nil, auth)

		req := httptest.NewRequest(http.MethodGet, "/audit", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "token"})
		rec := httptest.NewRecorder()
		h.HandleAuditPage(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("renders page for admin user", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return []store.AuditEntry{}, 0, nil
			},
		}
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			IsAdminFunc:        func(username string) bool { return true },
			EnabledFunc:        func() bool { return true },
		}
		h := newTestAuditHandler(t, auditStore, auth)

		req := httptest.NewRequest(http.MethodGet, "/audit", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "token"})
		rec := httptest.NewRecorder()
		h.HandleAuditPage(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "Audit Log")
	})
}

func TestAuditHandler_HandleAuditTable(t *testing.T) {
	t.Run("returns 401 for unauthenticated request", func(t *testing.T) {
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "", false },
		}
		h := newTestAuditHandler(t, nil, auth)

		req := httptest.NewRequest(http.MethodGet, "/web/audit", http.NoBody)
		// no session cookie
		rec := httptest.NewRecorder()
		h.HandleAuditTable(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("returns 403 for non-admin", func(t *testing.T) {
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "user", true },
			IsAdminFunc:        func(username string) bool { return false },
		}
		h := newTestAuditHandler(t, nil, auth)

		req := httptest.NewRequest(http.MethodGet, "/web/audit", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "token"})
		rec := httptest.NewRecorder()
		h.HandleAuditTable(rec, req)

		assert.Equal(t, http.StatusForbidden, rec.Code)
	})

	t.Run("returns table partial for admin", func(t *testing.T) {
		now := time.Now()
		valueSize := 1024
		entries := []store.AuditEntry{
			{ID: 1, Timestamp: now, Action: enum.AuditActionRead, Key: "test/key", Actor: "admin", ActorType: enum.ActorTypeUser, Result: enum.AuditResultSuccess, ValueSize: &valueSize},
		}
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return entries, 1, nil
			},
		}
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			IsAdminFunc:        func(username string) bool { return true },
			EnabledFunc:        func() bool { return true },
		}
		h := newTestAuditHandler(t, auditStore, auth)

		req := httptest.NewRequest(http.MethodGet, "/web/audit", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "token"})
		rec := httptest.NewRecorder()
		h.HandleAuditTable(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "test/key")
		assert.Contains(t, rec.Body.String(), "1.0 KB") // formatted ValueSize
	})
}

func TestAuditHandler_BuildAuditData(t *testing.T) {
	t.Run("parses filter parameters", func(t *testing.T) {
		var capturedQuery store.AuditQuery
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, q store.AuditQuery) ([]store.AuditEntry, int, error) {
				capturedQuery = q
				return []store.AuditEntry{}, 0, nil
			},
		}
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			IsAdminFunc:        func(username string) bool { return true },
			EnabledFunc:        func() bool { return true },
		}
		h := newTestAuditHandler(t, auditStore, auth)

		req := httptest.NewRequest(http.MethodGet, "/web/audit?key=app/*&actor=admin&action=read&result=success", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "token"})
		rec := httptest.NewRecorder()
		h.HandleAuditTable(rec, req)

		assert.Equal(t, "app/*", capturedQuery.Key)
		assert.Equal(t, "admin", capturedQuery.Actor)
		assert.Equal(t, enum.AuditActionRead, capturedQuery.Action)
		assert.Equal(t, enum.AuditResultSuccess, capturedQuery.Result)
		assert.Equal(t, 0, capturedQuery.Offset) // page 1 (default)
		assert.Equal(t, 100, capturedQuery.Limit)
	})

	t.Run("parses actor_type filter", func(t *testing.T) {
		var capturedQuery store.AuditQuery
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, q store.AuditQuery) ([]store.AuditEntry, int, error) {
				capturedQuery = q
				return []store.AuditEntry{}, 0, nil
			},
		}
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			IsAdminFunc:        func(username string) bool { return true },
			EnabledFunc:        func() bool { return true },
		}
		h := newTestAuditHandler(t, auditStore, auth)

		req := httptest.NewRequest(http.MethodGet, "/web/audit?actor_type=token", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "token"})
		rec := httptest.NewRecorder()
		h.HandleAuditTable(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, enum.ActorTypeToken, capturedQuery.ActorType)
	})

	t.Run("clamps page when exceeds total", func(t *testing.T) {
		callCount := 0
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, q store.AuditQuery) ([]store.AuditEntry, int, error) {
				callCount++
				if callCount == 1 {
					// first call returns empty due to high offset
					return []store.AuditEntry{}, 50, nil // total 50 entries, page size 100 = 1 page
				}
				// second call after clamping
				return []store.AuditEntry{{ID: 1, Key: "clamped"}}, 50, nil
			},
		}
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			IsAdminFunc:        func(username string) bool { return true },
			EnabledFunc:        func() bool { return true },
		}
		h := newTestAuditHandler(t, auditStore, auth)

		req := httptest.NewRequest(http.MethodGet, "/web/audit?page=999", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "token"})
		rec := httptest.NewRecorder()
		h.HandleAuditTable(rec, req)

		assert.Equal(t, 2, callCount, "should re-query after clamping")
		assert.Contains(t, rec.Body.String(), "clamped")
	})

	t.Run("invalid page values default to 1", func(t *testing.T) {
		var capturedQuery store.AuditQuery
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, q store.AuditQuery) ([]store.AuditEntry, int, error) {
				capturedQuery = q
				return []store.AuditEntry{}, 0, nil
			},
		}
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			IsAdminFunc:        func(username string) bool { return true },
			EnabledFunc:        func() bool { return true },
		}
		h := newTestAuditHandler(t, auditStore, auth)

		testCases := []struct{ page string }{
			{"0"},   // zero defaults to 1
			{"-5"},  // negative defaults to 1
			{"abc"}, // non-numeric defaults to 1
			{""},    // empty defaults to 1
		}

		for _, tc := range testCases {
			url := "/web/audit"
			if tc.page != "" {
				url += "?page=" + tc.page
			}
			req := httptest.NewRequest(http.MethodGet, url, http.NoBody)
			req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "token"})
			rec := httptest.NewRecorder()
			h.HandleAuditTable(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code, "page=%q should succeed", tc.page)
			assert.Equal(t, 0, capturedQuery.Offset, "page=%q should have offset 0 (page 1)", tc.page)
		}
	})

	t.Run("handles query error", func(t *testing.T) {
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return nil, 0, assert.AnError
			},
		}
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			IsAdminFunc:        func(username string) bool { return true },
			EnabledFunc:        func() bool { return true },
		}
		h := newTestAuditHandler(t, auditStore, auth)

		req := httptest.NewRequest(http.MethodGet, "/web/audit", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "token"})
		rec := httptest.NewRecorder()
		h.HandleAuditTable(rec, req)

		assert.Contains(t, rec.Body.String(), "Failed to query audit log")
	})

	t.Run("parses date range filters", func(t *testing.T) {
		var capturedQuery store.AuditQuery
		auditStore := &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, q store.AuditQuery) ([]store.AuditEntry, int, error) {
				capturedQuery = q
				return []store.AuditEntry{}, 0, nil
			},
		}
		auth := &mocks.AuthProviderMock{
			GetSessionUserFunc: func(_ context.Context, _ string) (string, bool) { return "admin", true },
			IsAdminFunc:        func(username string) bool { return true },
			EnabledFunc:        func() bool { return true },
		}
		h := newTestAuditHandler(t, auditStore, auth)

		req := httptest.NewRequest(http.MethodGet, "/web/audit?from=2024-01-15T10:30&to=2024-01-20T15:45", http.NoBody)
		req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "token"})
		rec := httptest.NewRecorder()
		h.HandleAuditTable(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.False(t, capturedQuery.From.IsZero())
		assert.False(t, capturedQuery.To.IsZero())
		assert.Equal(t, 2024, capturedQuery.From.Year())
		assert.Equal(t, time.January, capturedQuery.From.Month())
		assert.Equal(t, 15, capturedQuery.From.Day())
	})
}

func TestAuditTemplateFuncs(t *testing.T) {
	funcs := AuditTemplateFuncs()

	t.Run("actionClass returns correct classes", func(t *testing.T) {
		actionClassFn := funcs["actionClass"].(func(enum.AuditAction) string)
		assert.Equal(t, "action-create", actionClassFn(enum.AuditActionCreate))
		assert.Equal(t, "action-read", actionClassFn(enum.AuditActionRead))
		assert.Equal(t, "action-update", actionClassFn(enum.AuditActionUpdate))
		assert.Equal(t, "action-delete", actionClassFn(enum.AuditActionDelete))
	})

	t.Run("resultClass returns correct classes", func(t *testing.T) {
		resultClassFn := funcs["resultClass"].(func(enum.AuditResult) string)
		assert.Equal(t, "result-success", resultClassFn(enum.AuditResultSuccess))
		assert.Equal(t, "result-denied", resultClassFn(enum.AuditResultDenied))
		assert.Equal(t, "result-not_found", resultClassFn(enum.AuditResultNotFound))
	})
}

// newTestAuditHandler creates a test audit handler with mocked dependencies.
func newTestAuditHandler(t *testing.T, auditStore AuditStore, auth AuthProvider) *AuditHandler {
	t.Helper()
	if auditStore == nil {
		auditStore = &mocks.AuditStoreMock{
			QueryAuditFunc: func(_ context.Context, _ store.AuditQuery) ([]store.AuditEntry, int, error) {
				return []store.AuditEntry{}, 0, nil
			},
		}
	}

	// create parent handler for template access
	st := &mocks.KVStoreMock{
		ListFunc:           func(context.Context, enum.SecretsFilter) ([]store.KeyInfo, error) { return nil, nil },
		SecretsEnabledFunc: func() bool { return false },
	}
	if auth == nil {
		auth = &mocks.AuthProviderMock{
			EnabledFunc: func() bool { return true },
		}
	}
	parentHandler, err := New(Deps{Store: st, Auth: auth, Validator: defaultValidatorMock()}, Config{})
	require.NoError(t, err)

	return NewAuditHandler(auditStore, auth, parentHandler)
}
