package sse

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/server/sse/mocks"
)

func TestKeyToTopics(t *testing.T) {
	tests := []struct {
		key    string
		topics []string
	}{
		{key: "app", topics: []string{"app", ""}},
		{key: "app/config", topics: []string{"app/config", "app/", ""}},
		{key: "app/config/db", topics: []string{"app/config/db", "app/config/", "app/", ""}},
		{key: "/app/config/", topics: []string{"app/config", "app/", ""}}, // normalized
		{key: "", topics: []string{""}},                                   // empty key returns single topic
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := keyToTopics(tt.key)
			assert.Equal(t, tt.topics, got)
		})
	}
}

func TestNormalizeKey(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"app/config", "app/config"},
		{"/app/config", "app/config"},
		{"app/config/", "app/config"},
		{"/app/config/", "app/config"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeKey(tt.input))
		})
	}
}

func TestService_OnSession_ValidationErrors(t *testing.T) {
	svc := New(nil)

	t.Run("no key path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/subscribe", http.NoBody)
		w := httptest.NewRecorder()

		topics, ok := svc.onSession(w, req)
		assert.False(t, ok)
		assert.Nil(t, topics)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestService_OnSession_ValidParams(t *testing.T) {
	svc := New(nil) // no auth

	t.Run("exact key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/subscribe/app/config", http.NoBody)
		req.SetPathValue("key", "app/config")
		w := httptest.NewRecorder()

		topics, ok := svc.onSession(w, req)
		assert.True(t, ok)
		assert.Equal(t, []string{"app/config"}, topics)
	})

	t.Run("prefix with wildcard", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/subscribe/app/*", http.NoBody)
		req.SetPathValue("key", "app/*")
		w := httptest.NewRecorder()

		topics, ok := svc.onSession(w, req)
		assert.True(t, ok)
		assert.Equal(t, []string{"app/"}, topics)
	})

	t.Run("prefix with trailing slash", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/subscribe/app/", http.NoBody)
		req.SetPathValue("key", "app/")
		w := httptest.NewRecorder()

		topics, ok := svc.onSession(w, req)
		assert.True(t, ok)
		assert.Equal(t, []string{"app/"}, topics)
	})

	t.Run("root wildcard", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/subscribe/*", http.NoBody)
		req.SetPathValue("key", "*")
		w := httptest.NewRecorder()

		topics, ok := svc.onSession(w, req)
		assert.True(t, ok)
		assert.Equal(t, []string{""}, topics)
	})
}

func TestService_OnSession_AuthDenied(t *testing.T) {
	auth := &mocks.AuthProviderMock{
		EnabledFunc: func() bool { return true },
		FilterKeysForRequestFunc: func(r *http.Request, keys []string) []string {
			return nil // deny all
		},
	}

	svc := New(auth)

	req := httptest.NewRequest("GET", "/subscribe/secret/data", http.NoBody)
	req.SetPathValue("key", "secret/data")
	w := httptest.NewRecorder()

	topics, ok := svc.onSession(w, req)
	assert.False(t, ok)
	assert.Nil(t, topics)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestService_OnSession_AuthAllowed(t *testing.T) {
	auth := &mocks.AuthProviderMock{
		EnabledFunc: func() bool { return true },
		FilterKeysForRequestFunc: func(r *http.Request, keys []string) []string {
			return keys // allow all
		},
	}

	svc := New(auth)

	req := httptest.NewRequest("GET", "/subscribe/app/config", http.NoBody)
	req.SetPathValue("key", "app/config")
	w := httptest.NewRecorder()

	topics, ok := svc.onSession(w, req)
	assert.True(t, ok)
	assert.Equal(t, []string{"app/config"}, topics)
}

func TestService_Shutdown(t *testing.T) {
	svc := New(nil)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	err := svc.Shutdown(ctx)
	require.NoError(t, err)
}

func TestService_Shutdown_WithActiveConnection(t *testing.T) {
	svc := New(nil)

	// start a test server with the SSE handler
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("key", "test/key")
		svc.ServeHTTP(w, r)
	}))
	defer server.Close()

	// create a client connection
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, http.NoBody)
	require.NoError(t, err)

	// start connection in background (will block until context canceled or server shutdown)
	connErr := make(chan error, 1)
	go func() {
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			connErr <- doErr
			return
		}
		_ = resp.Body.Close()
		connErr <- nil
	}()

	// give the connection time to establish
	time.Sleep(50 * time.Millisecond)

	// shutdown should complete even with active connection
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	err = svc.Shutdown(shutdownCtx)
	require.NoError(t, err)

	// cancel client context to trigger connection termination
	cancel()

	// wait for connection goroutine to complete and verify it was terminated
	select {
	case connResult := <-connErr:
		require.Error(t, connResult, "connection should be terminated after shutdown")
	case <-time.After(time.Second):
		t.Fatal("connection goroutine did not complete after shutdown")
	}
}
