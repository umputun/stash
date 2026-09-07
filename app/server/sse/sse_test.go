package sse

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/enum"
	"github.com/umputun/stash/app/server/auth"
	"github.com/umputun/stash/app/server/sse/mocks"
	"github.com/umputun/stash/app/store"
)

func TestSubscriber_Matches(t *testing.T) {
	tests := []struct {
		name string
		sub  subscriber
		key  string
		want bool
	}{
		{"exact match", subscriber{key: "app/config"}, "app/config", true},
		{"exact rejects child", subscriber{key: "app"}, "app/config", false},
		{"prefix matches child", subscriber{key: "app/", isPrefix: true}, "app/config/db", true},
		{"prefix rejects sibling", subscriber{key: "app/", isPrefix: true}, "application/x", false},
		{"root prefix matches all", subscriber{key: "", isPrefix: true}, "anything", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.sub.matches(tt.key))
		})
	}
}

func TestService_OnSession_ValidationErrors(t *testing.T) {
	svc := New(nil)

	t.Run("no key path", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/subscribe", http.NoBody)
		w := httptest.NewRecorder()

		topic, ok := svc.onSession(w, req)
		assert.False(t, ok)
		assert.Empty(t, topic)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestService_OnSession_ValidParams(t *testing.T) {
	tests := []struct {
		name    string
		rawPath string
		want    subscriber
	}{
		{"exact key", "app/config", subscriber{key: "app/config"}},
		{"prefix with wildcard", "app/*", subscriber{key: "app/", isPrefix: true}},
		{"prefix with trailing slash", "app/", subscriber{key: "app/", isPrefix: true}},
		{"root wildcard", "*", subscriber{key: "", isPrefix: true}},
		{"key with spaces normalized", "app config", subscriber{key: "app_config"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := New(nil)
			req := httptest.NewRequest("GET", "/subscribe/x", http.NoBody)
			req.SetPathValue("key", tt.rawPath)
			w := httptest.NewRecorder()

			topic, ok := svc.onSession(w, req)
			require.True(t, ok)
			require.NotEmpty(t, topic)

			svc.mu.RLock()
			sub, found := svc.subs[topic]
			svc.mu.RUnlock()
			require.True(t, found)
			assert.Equal(t, tt.want.key, sub.key)
			assert.Equal(t, tt.want.isPrefix, sub.isPrefix)
		})
	}
}

func TestService_OnSession_AuthDenied(t *testing.T) {
	authMock := &mocks.AuthProviderMock{
		EnabledFunc:              func() bool { return true },
		FilterKeysForRequestFunc: func(*http.Request, []string) []string { return nil },
	}
	svc := New(authMock)

	t.Run("exact key is refused", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/subscribe/secret/data", http.NoBody)
		req.SetPathValue("key", "secret/data")
		w := httptest.NewRecorder()

		topic, ok := svc.onSession(w, req)
		assert.False(t, ok)
		assert.Empty(t, topic)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("prefix is accepted and filtered per event", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/subscribe/secret/*", http.NoBody)
		req.SetPathValue("key", "secret/*")
		w := httptest.NewRecorder()

		topic, ok := svc.onSession(w, req)
		assert.True(t, ok)
		assert.NotEmpty(t, topic)
	})
}

func TestService_OnSession_AuthAllowed(t *testing.T) {
	authMock := &mocks.AuthProviderMock{
		EnabledFunc:              func() bool { return true },
		FilterKeysForRequestFunc: func(_ *http.Request, keys []string) []string { return keys },
	}
	svc := New(authMock)

	req := httptest.NewRequest("GET", "/subscribe/app/config", http.NoBody)
	req.SetPathValue("key", "app/config")
	w := httptest.NewRecorder()

	topic, ok := svc.onSession(w, req)
	assert.True(t, ok)
	assert.NotEmpty(t, topic)
}

func TestService_OnSession_CleanupOnDisconnect(t *testing.T) {
	svc := New(nil)
	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest("GET", "/subscribe/app/*", http.NoBody).WithContext(ctx)
	req.SetPathValue("key", "app/*")

	_, ok := svc.onSession(httptest.NewRecorder(), req)
	require.True(t, ok)
	svc.mu.RLock()
	assert.Len(t, svc.subs, 1)
	svc.mu.RUnlock()

	cancel()
	assert.Eventually(t, func() bool {
		svc.mu.RLock()
		defer svc.mu.RUnlock()
		return len(svc.subs) == 0
	}, time.Second, 10*time.Millisecond)
}

// pins the leak where a prefix subscriber received events naming keys its acl could not read
func TestService_Publish_FiltersPerSubscriber(t *testing.T) {
	authMock := &mocks.AuthProviderMock{
		EnabledFunc: func() bool { return true },
		FilterKeysForRequestFunc: func(r *http.Request, keys []string) []string {
			var res []string
			for _, k := range keys {
				if strings.HasPrefix(k, r.Header.Get("X-Allow")) {
					res = append(res, k)
				}
			}
			return res
		},
	}
	svc := New(authMock)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("key", strings.TrimPrefix(r.URL.Path, "/subscribe/"))
		svc.ServeHTTP(w, r)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	admin := openStream(ctx, t, server.URL+"/subscribe/*", "X-Allow", "")
	appOnly := openStream(ctx, t, server.URL+"/subscribe/*", "X-Allow", "app/")
	other := openStream(ctx, t, server.URL+"/subscribe/other/*", "X-Allow", "app/")

	assert.Eventually(t, func() bool {
		svc.mu.RLock()
		defer svc.mu.RUnlock()
		return len(svc.subs) == 3
	}, time.Second, 10*time.Millisecond)

	svc.Publish("app/config", enum.AuditActionCreate)
	svc.Publish("app/secrets/db", enum.AuditActionUpdate)
	svc.Publish("db/host", enum.AuditActionDelete)

	assert.Equal(t, []string{"app/config", "app/secrets/db", "db/host"}, admin.keys(3))
	assert.Equal(t, []string{"app/config", "app/secrets/db"}, appOnly.keys(2))
	assert.Empty(t, other.keys(0))

	cancel()
	assert.Eventually(t, func() bool {
		svc.mu.RLock()
		defer svc.mu.RUnlock()
		return len(svc.subs) == 0
	}, 2*time.Second, 10*time.Millisecond)
}

func TestService_Publish_RealACL(t *testing.T) {
	authFile := t.TempDir() + "/auth.yml"
	require.NoError(t, os.WriteFile(authFile, []byte(`
tokens:
  - token: "wild"
    permissions:
      - prefix: "*"
        access: r
  - token: "sec"
    permissions:
      - prefix: "*"
        access: r
      - prefix: "app/secrets/*"
        access: r
`), 0o600))
	sessions, err := store.New(":memory:")
	require.NoError(t, err)
	defer sessions.Close()
	authSvc, err := auth.New(authFile, time.Hour, false, sessions, nil)
	require.NoError(t, err)
	svc := New(authSvc)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("key", strings.TrimPrefix(r.URL.Path, "/subscribe/"))
		svc.ServeHTTP(w, r)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	wild := openStream(ctx, t, server.URL+"/subscribe/*", "X-Auth-Token", "wild")
	sec := openStream(ctx, t, server.URL+"/subscribe/*", "X-Auth-Token", "sec")
	wildApp := openStream(ctx, t, server.URL+"/subscribe/app/*", "X-Auth-Token", "wild")

	assert.Eventually(t, func() bool {
		svc.mu.RLock()
		defer svc.mu.RUnlock()
		return len(svc.subs) == 3
	}, time.Second, 10*time.Millisecond)

	svc.Publish("app/config", enum.AuditActionCreate)
	svc.Publish("app/secrets/db", enum.AuditActionUpdate)
	svc.Publish("secrets/root", enum.AuditActionUpdate)
	svc.Publish("db/host", enum.AuditActionDelete)

	assert.Equal(t, []string{"app/config", "db/host"}, wild.keys(2))
	assert.Equal(t, []string{"app/config", "app/secrets/db", "db/host"}, sec.keys(3))
	assert.Equal(t, []string{"app/config"}, wildApp.keys(1))
}

func TestService_Shutdown_WaitsForBlockedFlush(t *testing.T) {
	svc := New(nil)
	w := &blockingWriter{header: http.Header{}, entered: make(chan struct{}, 1), release: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req := httptest.NewRequest(http.MethodGet, "/subscribe/k", http.NoBody).WithContext(ctx)
	req.SetPathValue("key", "k")

	served := make(chan struct{})
	go func() {
		svc.ServeHTTP(w, req)
		close(served)
	}()
	require.Eventually(t, func() bool {
		svc.mu.RLock()
		defer svc.mu.RUnlock()
		return len(svc.subs) == 1
	}, time.Second, 10*time.Millisecond)

	w.block.Store(true)
	go svc.Publish("k", enum.AuditActionCreate)
	select {
	case <-w.entered:
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not reach flush")
	}

	cancel()
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shutdownCancel()
	require.ErrorIs(t, svc.Shutdown(shutdownCtx), context.DeadlineExceeded)

	select {
	case <-served:
		t.Fatal("handler returned while dispatcher flush was blocked")
	case <-time.After(200 * time.Millisecond):
	}

	close(w.release)
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not return after flush was released")
	}

	laterCtx, laterCancel := context.WithTimeout(context.Background(), time.Second)
	defer laterCancel()
	require.NoError(t, svc.Shutdown(laterCtx))
}

func TestService_Publish_NoSubscribers(t *testing.T) {
	svc := New(nil)
	svc.Publish("app/config", enum.AuditActionCreate)
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

	// start connection in background, read from SSE stream (blocks until server closes)
	connDone := make(chan struct{}, 1)
	go func() {
		defer func() { connDone <- struct{}{} }()
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			return
		}
		defer resp.Body.Close()
		// read blocks until server shuts down and closes the connection
		buf := make([]byte, 1024)
		for {
			if _, readErr := resp.Body.Read(buf); readErr != nil {
				return
			}
		}
	}()

	// give the connection time to establish
	time.Sleep(50 * time.Millisecond)

	// shutdown should complete even with active connection
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()

	err = svc.Shutdown(shutdownCtx)
	require.NoError(t, err)

	// verify connection goroutine completed (server closed the connection)
	select {
	case <-connDone:
		// connection terminated after shutdown, as expected
	case <-time.After(time.Second):
		cancel() // clean up
		t.Fatal("connection goroutine did not complete after shutdown")
	}
}

type blockingWriter struct {
	header  http.Header
	block   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (w *blockingWriter) Header() http.Header         { return w.header }
func (w *blockingWriter) WriteHeader(int)             {}
func (w *blockingWriter) Write(b []byte) (int, error) { return len(b), nil }

func (w *blockingWriter) Flush() {
	if !w.block.Load() {
		return
	}
	select {
	case w.entered <- struct{}{}:
	default:
	}
	<-w.release
}

type stream struct {
	events chan string
}

func (s *stream) keys(n int) []string {
	var got []string
	deadline := time.After(3 * time.Second)
	for len(got) < n {
		select {
		case k := <-s.events:
			got = append(got, k)
		case <-deadline:
			return got
		}
	}
	grace := time.After(200 * time.Millisecond)
	for {
		select {
		case k := <-s.events:
			got = append(got, k)
		case <-grace:
			return got
		}
	}
}

func openStream(ctx context.Context, t *testing.T, url, header, value string) *stream {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	require.NoError(t, err)
	req.Header.Set(header, value)

	s := &stream{events: make(chan string, 16)}
	go func() {
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("unexpected status %d for %s", resp.StatusCode, url)
			return
		}
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var ev Event
			if jsonErr := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &ev); jsonErr == nil {
				s.events <- ev.Key
			}
		}
	}()
	return s
}
