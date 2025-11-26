package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCached_GetWithFormat(t *testing.T) {
	t.Run("caches on first read, returns cached on second", func(t *testing.T) {
		dbPath := t.TempDir() + "/test.db"
		underlying, err := New(dbPath)
		require.NoError(t, err)
		defer underlying.Close()

		cached, err := NewCached(underlying, 100)
		require.NoError(t, err)

		// set a value
		require.NoError(t, cached.Set("key1", []byte("value1"), "json"))

		// first read - loads from DB
		val, format, err := cached.GetWithFormat("key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), val)
		assert.Equal(t, "json", format)

		// check stats - should have 1 miss (first load)
		stats := cached.Stats()
		assert.Equal(t, int64(1), stats.Misses)
		assert.Equal(t, int64(0), stats.Hits)

		// second read - should hit cache
		val2, format2, err := cached.GetWithFormat("key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), val2)
		assert.Equal(t, "json", format2)

		// check stats - should have 1 hit now
		stats = cached.Stats()
		assert.Equal(t, int64(1), stats.Misses)
		assert.Equal(t, int64(1), stats.Hits)
	})

	t.Run("invalidates cache on Set", func(t *testing.T) {
		dbPath := t.TempDir() + "/test.db"
		underlying, err := New(dbPath)
		require.NoError(t, err)
		defer underlying.Close()

		cached, err := NewCached(underlying, 100)
		require.NoError(t, err)

		// set and read to populate cache
		require.NoError(t, cached.Set("key1", []byte("value1"), "text"))
		_, _, err = cached.GetWithFormat("key1")
		require.NoError(t, err)

		// update the value
		require.NoError(t, cached.Set("key1", []byte("updated"), "yaml"))

		// read again - should get updated value from DB (cache miss)
		val, format, err := cached.GetWithFormat("key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated"), val)
		assert.Equal(t, "yaml", format)

		// should have 2 misses (initial load + after invalidation)
		stats := cached.Stats()
		assert.Equal(t, int64(2), stats.Misses)
	})

	t.Run("invalidates cache on Delete", func(t *testing.T) {
		dbPath := t.TempDir() + "/test.db"
		underlying, err := New(dbPath)
		require.NoError(t, err)
		defer underlying.Close()

		cached, err := NewCached(underlying, 100)
		require.NoError(t, err)

		// set and read to populate cache
		require.NoError(t, cached.Set("key1", []byte("value1"), "text"))
		_, _, err = cached.GetWithFormat("key1")
		require.NoError(t, err)

		// delete the key
		require.NoError(t, cached.Delete("key1"))

		// read again - should get ErrNotFound
		_, _, err = cached.GetWithFormat("key1")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("returns ErrNotFound for missing key", func(t *testing.T) {
		dbPath := t.TempDir() + "/test.db"
		underlying, err := New(dbPath)
		require.NoError(t, err)
		defer underlying.Close()

		cached, err := NewCached(underlying, 100)
		require.NoError(t, err)

		_, _, err = cached.GetWithFormat("nonexistent")
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestCached_Get(t *testing.T) {
	t.Run("caches and returns value without format", func(t *testing.T) {
		dbPath := t.TempDir() + "/test.db"
		underlying, err := New(dbPath)
		require.NoError(t, err)
		defer underlying.Close()

		cached, err := NewCached(underlying, 100)
		require.NoError(t, err)

		require.NoError(t, cached.Set("key1", []byte("value1"), "text"))

		// first read
		val, err := cached.Get("key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), val)

		// second read should hit cache
		val2, err := cached.Get("key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), val2)

		stats := cached.Stats()
		assert.Equal(t, int64(1), stats.Hits)
	})
}

func TestCached_List(t *testing.T) {
	t.Run("delegates to underlying store", func(t *testing.T) {
		dbPath := t.TempDir() + "/test.db"
		underlying, err := New(dbPath)
		require.NoError(t, err)
		defer underlying.Close()

		cached, err := NewCached(underlying, 100)
		require.NoError(t, err)

		require.NoError(t, cached.Set("key1", []byte("value1"), "text"))
		require.NoError(t, cached.Set("key2", []byte("value2"), "json"))

		keys, err := cached.List()
		require.NoError(t, err)
		assert.Len(t, keys, 2)
	})
}

func TestCached_Close(t *testing.T) {
	t.Run("closes cache and underlying store", func(t *testing.T) {
		dbPath := t.TempDir() + "/test.db"
		underlying, err := New(dbPath)
		require.NoError(t, err)

		cached, err := NewCached(underlying, 100)
		require.NoError(t, err)

		require.NoError(t, cached.Close())

		// underlying store should be closed - operations should fail
		_, err = underlying.Get("key1")
		assert.Error(t, err) // should fail because DB is closed
	})
}
