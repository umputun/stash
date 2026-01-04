package stash

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Subscribe(t *testing.T) {
	// create test server that sends SSE events
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/kv/subscribe/app/config", r.URL.Path)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusOK)

		event := Event{Key: "app/config", Action: "update", Timestamp: "2025-01-03T10:30:00Z"}
		data, _ := json.Marshal(event)

		// send event
		_, _ = w.Write([]byte("event: change\n"))
		_, _ = w.Write([]byte("data: " + string(data) + "\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		// keep connection open briefly
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	client, err := New(server.URL)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sub, err := client.Subscribe(ctx, "app/config")
	require.NoError(t, err)
	defer sub.Close()

	// receive event
	select {
	case ev := <-sub.Events():
		assert.Equal(t, "app/config", ev.Key)
		assert.Equal(t, "update", ev.Action)
		assert.Equal(t, "2025-01-03T10:30:00Z", ev.Timestamp)
	case err := <-sub.Errors():
		t.Fatalf("unexpected error: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for event")
	}
}

func TestClient_SubscribePrefix(t *testing.T) {
	// create test server that sends SSE events
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/kv/subscribe/app/*", r.URL.Path)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		event := Event{Key: "app/db", Action: "create", Timestamp: "2025-01-03T10:31:00Z"}
		data, _ := json.Marshal(event)

		_, _ = w.Write([]byte("event: change\n"))
		_, _ = w.Write([]byte("data: " + string(data) + "\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	client, err := New(server.URL)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sub, err := client.SubscribePrefix(ctx, "app")
	require.NoError(t, err)
	defer sub.Close()

	select {
	case ev := <-sub.Events():
		assert.Equal(t, "app/db", ev.Key)
		assert.Equal(t, "create", ev.Action)
	case err := <-sub.Errors():
		t.Fatalf("unexpected error: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for event")
	}
}

func TestClient_SubscribeAll(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/kv/subscribe/*", r.URL.Path)

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		event := Event{Key: "any/key", Action: "delete", Timestamp: "2025-01-03T10:32:00Z"}
		data, _ := json.Marshal(event)

		_, _ = w.Write([]byte("event: change\n"))
		_, _ = w.Write([]byte("data: " + string(data) + "\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	client, err := New(server.URL)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	sub, err := client.SubscribeAll(ctx)
	require.NoError(t, err)
	defer sub.Close()

	select {
	case ev := <-sub.Events():
		assert.Equal(t, "any/key", ev.Key)
		assert.Equal(t, "delete", ev.Action)
	case err := <-sub.Errors():
		t.Fatalf("unexpected error: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for event")
	}
}

func TestClient_Subscribe_EmptyKey(t *testing.T) {
	client, err := New("http://localhost:8080")
	require.NoError(t, err)

	_, err = client.Subscribe(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key is required")
}

func TestClient_SubscribePrefix_EmptyPrefix(t *testing.T) {
	client, err := New("http://localhost:8080")
	require.NoError(t, err)

	_, err = client.SubscribePrefix(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "prefix is required")
}

func TestClient_Subscribe_CloseTerminatesConnection(t *testing.T) {
	// track if server connection was closed (use sync.Once to guard against retries)
	connClosed := make(chan struct{})
	var closeOnce sync.Once

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		// send initial event
		event := Event{Key: "test/key", Action: "create", Timestamp: "2025-01-03T10:30:00Z"}
		data, _ := json.Marshal(event)
		_, _ = w.Write([]byte("event: change\ndata: " + string(data) + "\n\n"))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}

		// wait for client to disconnect (context canceled)
		<-r.Context().Done()
		closeOnce.Do(func() { close(connClosed) })
	}))
	defer server.Close()

	client, err := New(server.URL)
	require.NoError(t, err)

	// use background context (no timeout) to verify Close() terminates
	sub, err := client.Subscribe(context.Background(), "test/key")
	require.NoError(t, err)

	// wait for event to confirm connection is established
	select {
	case <-sub.Events():
		// got event, connection established
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for initial event")
	}

	// call Close() - should terminate connection
	sub.Close()

	// verify server saw the connection close
	select {
	case <-connClosed:
		// connection was properly terminated
	case <-time.After(2 * time.Second):
		t.Fatal("Close() did not terminate the connection")
	}

	// verify both channels are closed
	select {
	case _, ok := <-sub.Events():
		assert.False(t, ok, "events channel should be closed")
	case <-time.After(time.Second):
		t.Fatal("events channel not closed after Close()")
	}

	select {
	case _, ok := <-sub.Errors():
		assert.False(t, ok, "errors channel should be closed")
	case <-time.After(time.Second):
		t.Fatal("errors channel not closed after Close()")
	}
}
