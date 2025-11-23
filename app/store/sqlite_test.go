package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSQLite(t *testing.T) {
	t.Run("creates database successfully", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "test.db")
		store, err := NewSQLite(dbPath)
		require.NoError(t, err)
		defer store.Close()
		assert.NotNil(t, store.db)
	})

	t.Run("fails with invalid path", func(t *testing.T) {
		_, err := NewSQLite("/nonexistent/dir/test.db")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to connect")
	})
}

func TestSQLite_SetGet(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	t.Run("set and get value", func(t *testing.T) {
		err := store.Set("key1", []byte("value1"))
		require.NoError(t, err)

		value, err := store.Get("key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), value)
	})

	t.Run("update existing key", func(t *testing.T) {
		err := store.Set("key2", []byte("original"))
		require.NoError(t, err)

		err = store.Set("key2", []byte("updated"))
		require.NoError(t, err)

		value, err := store.Get("key2")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated"), value)
	})

	t.Run("get nonexistent key returns ErrNotFound", func(t *testing.T) {
		_, err := store.Get("nonexistent")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("handles binary data", func(t *testing.T) {
		binary := []byte{0x00, 0x01, 0xFF, 0xFE}
		err := store.Set("binary", binary)
		require.NoError(t, err)

		value, err := store.Get("binary")
		require.NoError(t, err)
		assert.Equal(t, binary, value)
	})

	t.Run("handles empty value", func(t *testing.T) {
		err := store.Set("empty", []byte{})
		require.NoError(t, err)

		value, err := store.Get("empty")
		require.NoError(t, err)
		assert.Empty(t, value)
	})
}

func TestSQLite_UpdatedAt(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	// set initial value
	err := store.Set("timekey", []byte("v1"))
	require.NoError(t, err)

	// get created_at
	var created, updated1 string
	err = store.db.Get(&created, "SELECT created_at FROM kv WHERE key = ?", "timekey")
	require.NoError(t, err)
	err = store.db.Get(&updated1, "SELECT updated_at FROM kv WHERE key = ?", "timekey")
	require.NoError(t, err)
	assert.Equal(t, created, updated1, "created_at and updated_at should match on insert")

	// update value (wait to ensure different timestamp - RFC3339 has second precision)
	time.Sleep(1100 * time.Millisecond)
	err = store.Set("timekey", []byte("v2"))
	require.NoError(t, err)

	// verify updated_at changed but created_at didn't
	var created2, updated2 string
	err = store.db.Get(&created2, "SELECT created_at FROM kv WHERE key = ?", "timekey")
	require.NoError(t, err)
	err = store.db.Get(&updated2, "SELECT updated_at FROM kv WHERE key = ?", "timekey")
	require.NoError(t, err)

	assert.Equal(t, created, created2, "created_at should not change on update")
	assert.NotEqual(t, updated1, updated2, "updated_at should change on update")
}

func TestSQLite_Delete(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	t.Run("delete existing key", func(t *testing.T) {
		err := store.Set("todelete", []byte("value"))
		require.NoError(t, err)

		err = store.Delete("todelete")
		require.NoError(t, err)

		_, err = store.Get("todelete")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete nonexistent key returns ErrNotFound", func(t *testing.T) {
		err := store.Delete("nonexistent")
		require.ErrorIs(t, err, ErrNotFound)
	})
}

func newTestStore(t *testing.T) *SQLite {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	return store
}
