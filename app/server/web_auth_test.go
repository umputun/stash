package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/mocks"
	"github.com/umputun/stash/app/store"
	"github.com/umputun/stash/app/validator"
)

func TestHandleLoginForm(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createTestAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/login", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "Login")
	assert.Contains(t, rec.Body.String(), "Username")
	assert.Contains(t, rec.Body.String(), "Password")
}

func TestHandleLogin(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createTestAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	t.Run("valid credentials redirects", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"username": {"admin"}, "password": {"testpass"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

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
		req := httptest.NewRequest(http.MethodPost, "/login", http.NoBody)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.PostForm = map[string][]string{"username": {"admin"}, "password": {"wrongpass"}}
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Body.String(), "Invalid username or password")
	})
}

func TestHandleLogout(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createTestAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/logout", http.NoBody)
	req.AddCookie(&http.Cookie{Name: "stash-auth", Value: "somesession"})
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "/login", rec.Header().Get("Location"))
	// should clear cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "stash-auth" {
			assert.Equal(t, -1, c.MaxAge)
		}
	}
}

func TestLoginThrottle(t *testing.T) {
	st := &mocks.KVStoreMock{
		ListFunc: func() ([]store.KeyInfo, error) { return nil, nil },
	}
	authFile := createTestAuthFile(t)
	srv, err := New(st, validator.NewService(), Config{Address: ":8080", ReadTimeout: 5 * time.Second, AuthFile: authFile})
	require.NoError(t, err)

	// use httptest.Server for true concurrent requests
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	// login throttle is set to 5 concurrent requests
	// send 15 concurrent requests to ensure some get throttled
	// use valid credentials so bcrypt runs and keeps requests in flight longer
	const numRequests = 15
	var wg sync.WaitGroup
	var throttledCount atomic.Int32
	var successCount atomic.Int32
	var otherCount atomic.Int32

	// use a channel to synchronize start
	start := make(chan struct{})

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // wait for signal to start

			// send valid credentials so bcrypt runs (~50ms) keeping requests in flight
			resp, err := http.PostForm(ts.URL+"/login", map[string][]string{
				"username": {"admin"},
				"password": {"testpass"},
			})
			if err != nil {
				return
			}
			defer resp.Body.Close()

			switch resp.StatusCode {
			case http.StatusOK, http.StatusBadRequest, http.StatusSeeOther, http.StatusUnauthorized:
				// these are valid responses (login succeeded/failed/redirected)
				successCount.Add(1)
			case http.StatusServiceUnavailable: // throttled
				throttledCount.Add(1)
			default:
				otherCount.Add(1)
				t.Logf("unexpected status: %d", resp.StatusCode)
			}
		}()
	}

	// start all goroutines simultaneously
	close(start)
	wg.Wait()

	// with 15 concurrent requests and limit of 5, some should be throttled
	t.Logf("success: %d, throttled: %d, other: %d", successCount.Load(), throttledCount.Load(), otherCount.Load())
	assert.Positive(t, throttledCount.Load(), "some requests should be throttled")
	assert.Equal(t, int32(numRequests), successCount.Load()+throttledCount.Load()+otherCount.Load(), "all requests should complete")
}
