package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/mocks"
	"github.com/umputun/stash/app/store"
)

func TestServer_handleServiceRegister(t *testing.T) {
	svcStore := &mocks.ServiceStoreMock{
		RegisterServiceFunc: func(svc store.ServiceInstance) error {
			return nil
		},
	}

	srv := newTestServerWithServices(t, svcStore)

	t.Run("register service with TTL check", func(t *testing.T) {
		body := `{"address":"10.0.0.1","port":8080,"tags":["primary"],"check":{"type":"ttl","ttl":30}}`
		req := httptest.NewRequest(http.MethodPut, "/service/api", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var resp serviceRegisterResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Contains(t, resp.ID, "svc-")
		assert.Len(t, svcStore.RegisterServiceCalls(), 1)
	})

	t.Run("register service with HTTP check", func(t *testing.T) {
		body := `{"address":"10.0.0.1","port":8080,"check":{"type":"http","url":"http://10.0.0.1:8080/health","interval":10}}`
		req := httptest.NewRequest(http.MethodPut, "/service/api", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("register service with custom ID", func(t *testing.T) {
		body := `{"id":"my-custom-id","address":"10.0.0.1","port":8080}`
		req := httptest.NewRequest(http.MethodPut, "/service/api", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var resp serviceRegisterResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, "my-custom-id", resp.ID)
	})

	t.Run("missing address returns error", func(t *testing.T) {
		body := `{"port":8080}`
		req := httptest.NewRequest(http.MethodPut, "/service/api", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("invalid port returns error", func(t *testing.T) {
		body := `{"address":"10.0.0.1","port":0}`
		req := httptest.NewRequest(http.MethodPut, "/service/api", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("http check without url returns error", func(t *testing.T) {
		body := `{"address":"10.0.0.1","port":8080,"check":{"type":"http"}}`
		req := httptest.NewRequest(http.MethodPut, "/service/api", bytes.NewBufferString(body))
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})
}

func TestServer_handleServiceDeregister(t *testing.T) {
	t.Run("deregister existing service", func(t *testing.T) {
		svcStore := &mocks.ServiceStoreMock{
			DeregisterServiceFunc: func(name, id string) error {
				return nil
			},
		}
		srv := newTestServerWithServices(t, svcStore)

		req := httptest.NewRequest(http.MethodDelete, "/service/api/svc-123", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		calls := svcStore.DeregisterServiceCalls()
		require.Len(t, calls, 1)
		assert.Equal(t, "api", calls[0].Name)
		assert.Equal(t, "svc-123", calls[0].ID)
	})

	t.Run("deregister nonexistent service returns 404", func(t *testing.T) {
		svcStore := &mocks.ServiceStoreMock{
			DeregisterServiceFunc: func(name, id string) error {
				return store.ErrServiceNotFound
			},
		}
		srv := newTestServerWithServices(t, svcStore)

		req := httptest.NewRequest(http.MethodDelete, "/service/api/svc-unknown", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestServer_handleServiceHealth(t *testing.T) {
	t.Run("update health of existing service", func(t *testing.T) {
		svcStore := &mocks.ServiceStoreMock{
			UpdateServiceHealthFunc: func(name, id string) error {
				return nil
			},
		}
		srv := newTestServerWithServices(t, svcStore)

		req := httptest.NewRequest(http.MethodPut, "/service/api/svc-123/health", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		calls := svcStore.UpdateServiceHealthCalls()
		require.Len(t, calls, 1)
		assert.Equal(t, "api", calls[0].Name)
		assert.Equal(t, "svc-123", calls[0].ID)
	})

	t.Run("update health of nonexistent service returns 404", func(t *testing.T) {
		svcStore := &mocks.ServiceStoreMock{
			UpdateServiceHealthFunc: func(name, id string) error {
				return store.ErrServiceNotFound
			},
		}
		srv := newTestServerWithServices(t, svcStore)

		req := httptest.NewRequest(http.MethodPut, "/service/api/svc-unknown/health", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestServer_handleServiceDiscover(t *testing.T) {
	services := []store.ServiceInstance{
		{ID: "svc-1", Name: "api", Address: "10.0.0.1", Port: 8080, Tags: []string{"primary"}, Healthy: true},
		{ID: "svc-2", Name: "api", Address: "10.0.0.2", Port: 8080, Tags: []string{"secondary"}, Healthy: true},
	}

	t.Run("get services by name", func(t *testing.T) {
		svcStore := &mocks.ServiceStoreMock{
			GetServicesFunc: func(name string, healthyOnly bool) ([]store.ServiceInstance, error) {
				return services, nil
			},
		}
		srv := newTestServerWithServices(t, svcStore)

		req := httptest.NewRequest(http.MethodGet, "/service/api", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var result []store.ServiceInstance
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
		assert.Len(t, result, 2)
	})

	t.Run("filter by tag", func(t *testing.T) {
		svcStore := &mocks.ServiceStoreMock{
			GetServicesFunc: func(name string, healthyOnly bool) ([]store.ServiceInstance, error) {
				return services, nil
			},
		}
		srv := newTestServerWithServices(t, svcStore)

		req := httptest.NewRequest(http.MethodGet, "/service/api?tag=primary", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var result []store.ServiceInstance
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
		assert.Len(t, result, 1)
		assert.Equal(t, "svc-1", result[0].ID)
	})
}

func TestServer_handleServiceList(t *testing.T) {
	summaries := []store.ServiceSummary{
		{Name: "api", Instances: 3, Healthy: 2},
		{Name: "db", Instances: 1, Healthy: 1},
	}

	svcStore := &mocks.ServiceStoreMock{
		ListServicesSummaryFunc: func() ([]store.ServiceSummary, error) {
			return summaries, nil
		},
	}
	srv := newTestServerWithServices(t, svcStore)

	req := httptest.NewRequest(http.MethodGet, "/services", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	var result []store.ServiceSummary
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &result))
	assert.Len(t, result, 2)
}

func newTestServerWithServices(t *testing.T, svcSt ServiceStore) *Server {
	t.Helper()
	srv, err := New(nil, svcSt, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test"})
	require.NoError(t, err)
	return srv
}
