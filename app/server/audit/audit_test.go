package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/server/audit/mocks"
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

	t.Run("flush delegates to underlying flusher", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rc := newResponseCapture(rec)

		// httptest.ResponseRecorder implements http.Flusher, so Flush should work
		rc.Flush() // should not panic
		assert.True(t, rec.Flushed)
	})

	t.Run("hijack returns error for non-hijacker", func(t *testing.T) {
		rec := httptest.NewRecorder() // doesn't implement http.Hijacker
		rc := newResponseCapture(rec)

		conn, rw, err := rc.Hijack()

		assert.Nil(t, conn)
		assert.Nil(t, rw)
		assert.EqualError(t, err, "ResponseWriter does not implement http.Hijacker")
	})

	t.Run("accumulates bytes across multiple writes", func(t *testing.T) {
		rec := httptest.NewRecorder()
		rc := newResponseCapture(rec)

		_, _ = rc.Write([]byte("first"))
		_, _ = rc.Write([]byte("second"))
		_, _ = rc.Write([]byte("third"))

		assert.Equal(t, 16, rc.bytesWritten) // 5 + 6 + 5
	})
}

func TestNoopMiddleware(t *testing.T) {
	t.Run("passes through unchanged", func(t *testing.T) {
		handlerCalled := false
		innerHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte("I'm a teapot"))
		})

		handler := NoopMiddleware(innerHandler)

		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusTeapot, rec.Code)
		assert.Equal(t, "I'm a teapot", rec.Body.String())
	})
}

func TestMiddleware(t *testing.T) {
	t.Run("logs audit entry for kv GET", func(t *testing.T) {
		var capturedEntry store.AuditEntry
		auditStore := &mocks.StoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		auth := &mocks.AuthMock{
			GetRequestActorFunc: func(_ *http.Request) (string, string) {
				return "user", "testuser"
			},
			IsRequestAdminFunc: func(_ *http.Request) bool { return false },
		}
		middleware := Middleware(auditStore, auth)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		auditStore := &mocks.StoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		auth := &mocks.AuthMock{
			GetRequestActorFunc: func(_ *http.Request) (string, string) {
				return "token", "token:myto****"
			},
			IsRequestAdminFunc: func(_ *http.Request) bool { return false },
		}
		middleware := Middleware(auditStore, auth)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		auditStore := &mocks.StoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := Middleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		auditStore := &mocks.StoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := Middleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		auditStore := &mocks.StoreMock{
			LogAuditFunc: func(_ context.Context, _ store.AuditEntry) error {
				return nil
			},
		}

		middleware := Middleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/other/path", http.NoBody)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		assert.Empty(t, auditStore.LogAuditCalls())
	})

	t.Run("skips kv list operation", func(t *testing.T) {
		auditStore := &mocks.StoreMock{
			LogAuditFunc: func(_ context.Context, _ store.AuditEntry) error {
				return nil
			},
		}

		middleware := Middleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		auditStore := &mocks.StoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := Middleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		auditStore := &mocks.StoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := Middleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
		auditStore := &mocks.StoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := Middleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/kv//app///config/", http.NoBody)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Len(t, auditStore.LogAuditCalls(), 1)
		assert.Equal(t, "app///config", capturedEntry.Key) // only leading/trailing slashes trimmed
	})

	t.Run("continues on LogAudit error", func(t *testing.T) {
		auditStore := &mocks.StoreMock{
			LogAuditFunc: func(_ context.Context, _ store.AuditEntry) error {
				return assert.AnError // simulate storage failure
			},
		}

		middleware := Middleware(auditStore, nil)

		handlerCalled := false
		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("response"))
		}))

		req := httptest.NewRequest(http.MethodGet, "/kv/test/key", http.NoBody)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		// handler should still execute and return response
		assert.True(t, handlerCalled)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "response", rec.Body.String())
		// LogAudit should have been called
		require.Len(t, auditStore.LogAuditCalls(), 1)
	})

	t.Run("captures user agent and request id", func(t *testing.T) {
		var capturedEntry store.AuditEntry
		auditStore := &mocks.StoreMock{
			LogAuditFunc: func(_ context.Context, entry store.AuditEntry) error {
				capturedEntry = entry
				return nil
			},
		}

		middleware := Middleware(auditStore, nil)

		handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/kv/test/key", http.NoBody)
		req.Header.Set("User-Agent", "test-agent/1.0")
		req.Header.Set("X-Request-ID", "req-12345")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		require.Len(t, auditStore.LogAuditCalls(), 1)
		assert.Equal(t, "test-agent/1.0", capturedEntry.UserAgent)
		assert.Equal(t, "req-12345", capturedEntry.RequestID)
		assert.False(t, capturedEntry.Timestamp.IsZero())
	})
}

func TestLogger_MapAction(t *testing.T) {
	l := newLogger(nil, nil)

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
			got := l.mapAction(tt.method, tt.status)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLogger_MapStatus(t *testing.T) {
	l := newLogger(nil, nil)

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
			got := l.mapStatus(tt.status)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestLogger_ExtractActor(t *testing.T) {
	t.Run("nil auth returns anonymous", func(t *testing.T) {
		l := newLogger(nil, nil)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)
		actor, actorType := l.extractActor(req)
		assert.Equal(t, "anonymous", actor)
		assert.Equal(t, enum.ActorTypePublic, actorType)
	})

	t.Run("user actor", func(t *testing.T) {
		auth := &mocks.AuthMock{
			GetRequestActorFunc: func(_ *http.Request) (string, string) {
				return "user", "alice"
			},
			IsRequestAdminFunc: func(_ *http.Request) bool { return false },
		}
		l := newLogger(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)

		actor, actorType := l.extractActor(req)

		assert.Equal(t, "alice", actor)
		assert.Equal(t, enum.ActorTypeUser, actorType)
	})

	t.Run("token actor", func(t *testing.T) {
		auth := &mocks.AuthMock{
			GetRequestActorFunc: func(_ *http.Request) (string, string) {
				return "token", "token:abcd****"
			},
			IsRequestAdminFunc: func(_ *http.Request) bool { return false },
		}
		l := newLogger(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)

		actor, actorType := l.extractActor(req)

		assert.Equal(t, "token:abcd****", actor)
		assert.Equal(t, enum.ActorTypeToken, actorType)
	})

	t.Run("public actor", func(t *testing.T) {
		auth := &mocks.AuthMock{
			GetRequestActorFunc: func(_ *http.Request) (string, string) {
				return "public", ""
			},
			IsRequestAdminFunc: func(_ *http.Request) bool { return false },
		}
		l := newLogger(nil, auth)
		req := httptest.NewRequest(http.MethodGet, "/kv/test", http.NoBody)

		actor, actorType := l.extractActor(req)

		assert.Equal(t, "anonymous", actor)
		assert.Equal(t, enum.ActorTypePublic, actorType)
	})
}
