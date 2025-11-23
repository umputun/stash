package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/store"
)

func TestServer_HandleGet(t *testing.T) {
	st := newMockStore()
	srv := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test"})

	t.Run("get existing key", func(t *testing.T) {
		st.data["testkey"] = []byte("testvalue")

		req := httptest.NewRequest(http.MethodGet, "/kv/testkey", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "testvalue", rec.Body.String())
	})

	t.Run("get nonexistent key returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/kv/nonexistent", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})

	t.Run("get key with slashes", func(t *testing.T) {
		st.data["path/to/key"] = []byte("nested value")

		req := httptest.NewRequest(http.MethodGet, "/kv/path/to/key", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "nested value", rec.Body.String())
	})
}

func TestServer_HandleSet(t *testing.T) {
	st := newMockStore()
	srv := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test"})

	t.Run("set new key", func(t *testing.T) {
		body := bytes.NewBufferString("newvalue")
		req := httptest.NewRequest(http.MethodPut, "/kv/newkey", body)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, []byte("newvalue"), st.data["newkey"])
	})

	t.Run("update existing key", func(t *testing.T) {
		st.data["existing"] = []byte("old")

		body := bytes.NewBufferString("updated")
		req := httptest.NewRequest(http.MethodPut, "/kv/existing", body)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, []byte("updated"), st.data["existing"])
	})

	t.Run("set key with slashes", func(t *testing.T) {
		body := bytes.NewBufferString("nested")
		req := httptest.NewRequest(http.MethodPut, "/kv/a/b/c", body)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, []byte("nested"), st.data["a/b/c"])
	})
}

func TestServer_HandleDelete(t *testing.T) {
	st := newMockStore()
	srv := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test"})

	t.Run("delete existing key", func(t *testing.T) {
		st.data["todelete"] = []byte("value")

		req := httptest.NewRequest(http.MethodDelete, "/kv/todelete", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		_, exists := st.data["todelete"]
		assert.False(t, exists)
	})

	t.Run("delete nonexistent key returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/kv/nonexistent", http.NoBody)
		rec := httptest.NewRecorder()
		srv.routes().ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNotFound, rec.Code)
	})
}

func TestServer_Ping(t *testing.T) {
	st := newMockStore()
	srv := New(st, Config{Address: ":8080", ReadTimeout: 5 * time.Second, Version: "test"})

	req := httptest.NewRequest(http.MethodGet, "/ping", http.NoBody)
	rec := httptest.NewRecorder()
	srv.routes().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "pong", rec.Body.String())
}

// mockStore implements KVStore for testing
type mockStore struct {
	data map[string][]byte
}

func newMockStore() *mockStore {
	return &mockStore{data: make(map[string][]byte)}
}

func (m *mockStore) Get(key string) ([]byte, error) {
	if v, ok := m.data[key]; ok {
		return v, nil
	}
	return nil, store.ErrNotFound
}

func (m *mockStore) Set(key string, value []byte) error {
	m.data[key] = value
	return nil
}

func (m *mockStore) Delete(key string) error {
	if _, ok := m.data[key]; !ok {
		return store.ErrNotFound
	}
	delete(m.data, key)
	return nil
}
