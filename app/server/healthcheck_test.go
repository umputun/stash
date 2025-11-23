package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/mocks"
	"github.com/umputun/stash/app/store"
)

func TestHealthChecker_TTLExpiration(t *testing.T) {
	var markedUnhealthy atomic.Int32
	svcStore := &mocks.ServiceStoreMock{
		GetServicesForHealthCheckFunc: func(checkType store.HealthCheckType) ([]store.ServiceInstance, error) {
			if checkType != store.HealthCheckTTL {
				return nil, nil
			}
			return []store.ServiceInstance{
				{ID: "svc-1", Name: "api", TTL: 1, LastSeen: time.Now().Add(-5 * time.Second), Healthy: true}, // expired
				{ID: "svc-2", Name: "api", TTL: 30, LastSeen: time.Now(), Healthy: true},                      // not expired
				{ID: "svc-3", Name: "db", TTL: 1, LastSeen: time.Now().Add(-5 * time.Second), Healthy: false}, // already unhealthy
			}, nil
		},
		SetServiceHealthStatusFunc: func(name, id string, healthy bool) error {
			if !healthy {
				markedUnhealthy.Add(1)
			}
			return nil
		},
	}

	hc := NewHealthChecker(svcStore, HealthCheckerConfig{
		TTLCheckInterval:  50 * time.Millisecond,
		HTTPCheckInterval: 1 * time.Hour, // don't run HTTP checks
		HTTPCheckTimeout:  5 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	go hc.Run(ctx)
	<-ctx.Done()
	time.Sleep(50 * time.Millisecond) // allow goroutines to finish

	// only svc-1 should be marked unhealthy (svc-2 not expired, svc-3 already unhealthy)
	assert.GreaterOrEqual(t, markedUnhealthy.Load(), int32(1))
}

func TestHealthChecker_HTTPCheck(t *testing.T) {
	var healthyCount, unhealthyCount atomic.Int32

	// mock HTTP endpoint that returns 200
	healthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer healthyServer.Close()

	// mock HTTP endpoint that returns 500
	unhealthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer unhealthyServer.Close()

	svcStore := &mocks.ServiceStoreMock{
		GetServicesForHealthCheckFunc: func(checkType store.HealthCheckType) ([]store.ServiceInstance, error) {
			if checkType != store.HealthCheckHTTP {
				return nil, nil
			}
			return []store.ServiceInstance{
				{ID: "svc-1", Name: "api", CheckURL: healthyServer.URL, Healthy: false},       // will become healthy
				{ID: "svc-2", Name: "api", CheckURL: unhealthyServer.URL, Healthy: true},      // will become unhealthy
				{ID: "svc-3", Name: "db", CheckURL: healthyServer.URL, Healthy: true},         // stays healthy (no change)
				{ID: "svc-4", Name: "db", CheckURL: unhealthyServer.URL, Healthy: false},      // stays unhealthy (no change)
				{ID: "svc-5", Name: "cache", CheckURL: "http://invalid:99999", Healthy: true}, // unreachable, becomes unhealthy
			}, nil
		},
		SetServiceHealthStatusFunc: func(name, id string, healthy bool) error {
			if healthy {
				healthyCount.Add(1)
			} else {
				unhealthyCount.Add(1)
			}
			return nil
		},
	}

	hc := NewHealthChecker(svcStore, HealthCheckerConfig{
		TTLCheckInterval:  1 * time.Hour,
		HTTPCheckInterval: 50 * time.Millisecond,
		HTTPCheckTimeout:  100 * time.Millisecond,
	})

	// call checkHTTPServices directly to test the logic without depending on ticker timing
	ctx := context.Background()
	hc.checkHTTPServices(ctx)

	// svc-1 should become healthy, svc-2 and svc-5 should become unhealthy
	assert.Equal(t, int32(1), healthyCount.Load(), "svc-1 should become healthy")
	assert.Equal(t, int32(2), unhealthyCount.Load(), "svc-2 and svc-5 should become unhealthy")
}

func TestHealthChecker_HTTPCheckEndpoint(t *testing.T) {
	hc := NewHealthChecker(nil, HealthCheckerConfig{
		HTTPCheckTimeout: 1 * time.Second,
	})

	t.Run("healthy endpoint returns true", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		result := hc.checkHTTPEndpoint(context.Background(), srv.URL)
		assert.True(t, result)
	})

	t.Run("unhealthy endpoint returns false", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()

		result := hc.checkHTTPEndpoint(context.Background(), srv.URL)
		assert.False(t, result)
	})

	t.Run("all 2xx codes are healthy", func(t *testing.T) {
		for _, code := range []int{200, 201, 202, 204, 299} {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			}))
			result := hc.checkHTTPEndpoint(context.Background(), srv.URL)
			assert.True(t, result, "status %d should be healthy", code)
			srv.Close()
		}
	})

	t.Run("non-2xx codes are unhealthy", func(t *testing.T) {
		for _, code := range []int{301, 400, 401, 403, 404, 500, 502, 503} {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
			}))
			result := hc.checkHTTPEndpoint(context.Background(), srv.URL)
			assert.False(t, result, "status %d should be unhealthy", code)
			srv.Close()
		}
	})

	t.Run("unreachable endpoint returns false", func(t *testing.T) {
		result := hc.checkHTTPEndpoint(context.Background(), "http://127.0.0.1:59999")
		assert.False(t, result)
	})

	t.Run("invalid url returns false", func(t *testing.T) {
		result := hc.checkHTTPEndpoint(context.Background(), "not-a-url")
		assert.False(t, result)
	})
}

func TestHealthChecker_PerServiceInterval(t *testing.T) {
	var fastCount, slowCount atomic.Int32

	fastSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fastCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer fastSrv.Close()

	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slowCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowSrv.Close()

	svcStore := &mocks.ServiceStoreMock{
		GetServicesForHealthCheckFunc: func(checkType store.HealthCheckType) ([]store.ServiceInstance, error) {
			if checkType != store.HealthCheckHTTP {
				return nil, nil
			}
			return []store.ServiceInstance{
				{ID: "fast", Name: "api", CheckURL: fastSrv.URL, CheckInterval: 0, Healthy: true}, // uses global
				{ID: "slow", Name: "api", CheckURL: slowSrv.URL, CheckInterval: 5, Healthy: true}, // custom 5s
			}, nil
		},
		SetServiceHealthStatusFunc: func(name, id string, healthy bool) error {
			return nil
		},
	}

	hc := NewHealthChecker(svcStore, HealthCheckerConfig{
		TTLCheckInterval:  1 * time.Hour,
		HTTPCheckInterval: 100 * time.Millisecond, // global default
		HTTPCheckTimeout:  100 * time.Millisecond,
	})

	// first pass: fast is due, slow is too recent
	hc.lastCheckedMu.Lock()
	hc.lastChecked["fast"] = time.Now().Add(-200 * time.Millisecond) // overdue
	hc.lastChecked["slow"] = time.Now()                              // just checked
	hc.lastCheckedMu.Unlock()

	hc.checkHTTPServices(context.Background())
	assert.Equal(t, int32(1), fastCount.Load(), "fast service should be checked")
	assert.Equal(t, int32(0), slowCount.Load(), "slow service should be skipped")

	// second pass after intervals elapsed: both should be checked
	hc.lastCheckedMu.Lock()
	hc.lastChecked["fast"] = time.Now().Add(-2 * time.Second)
	hc.lastChecked["slow"] = time.Now().Add(-6 * time.Second) // beyond 5s interval
	hc.lastCheckedMu.Unlock()

	hc.checkHTTPServices(context.Background())
	assert.Equal(t, int32(2), fastCount.Load(), "fast service should be checked again")
	assert.Equal(t, int32(1), slowCount.Load(), "slow service should be checked once when due")
}

func TestHealthChecker_GracefulShutdown(t *testing.T) {
	svcStore := &mocks.ServiceStoreMock{
		GetServicesForHealthCheckFunc: func(checkType store.HealthCheckType) ([]store.ServiceInstance, error) {
			return nil, nil
		},
	}

	hc := NewHealthChecker(svcStore, HealthCheckerConfig{
		TTLCheckInterval:  10 * time.Millisecond,
		HTTPCheckInterval: 10 * time.Millisecond,
		HTTPCheckTimeout:  1 * time.Second,
	})

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		hc.Run(ctx)
		close(done)
	}()

	// let it run a bit
	time.Sleep(50 * time.Millisecond)

	// cancel and verify it stops
	cancel()

	select {
	case <-done:
		// success
	case <-time.After(1 * time.Second):
		require.Fail(t, "health checker did not stop within timeout")
	}
}
