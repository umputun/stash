package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-pkgz/testutils/containers"
	"github.com/jmoiron/sqlx"
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
		err := store.Set("key1", []byte("value1"), "text")
		require.NoError(t, err)

		value, err := store.Get("key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), value)
	})

	t.Run("update existing key", func(t *testing.T) {
		err := store.Set("key2", []byte("original"), "text")
		require.NoError(t, err)

		err = store.Set("key2", []byte("updated"), "text")
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
		err := store.Set("binary", binary, "text")
		require.NoError(t, err)

		value, err := store.Get("binary")
		require.NoError(t, err)
		assert.Equal(t, binary, value)
	})

	t.Run("handles empty value", func(t *testing.T) {
		err := store.Set("empty", []byte{}, "text")
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
	err := store.Set("timekey", []byte("v1"), "text")
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
	err = store.Set("timekey", []byte("v2"), "text")
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
		err := store.Set("todelete", []byte("value"), "text")
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

func TestSQLite_List(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	t.Run("empty store returns empty slice", func(t *testing.T) {
		keys, err := store.List()
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("returns keys with correct metadata", func(t *testing.T) {
		err := store.Set("key1", []byte("short"), "text")
		require.NoError(t, err)
		err = store.Set("key2", []byte("longer value here"), "json")
		require.NoError(t, err)

		keys, err := store.List()
		require.NoError(t, err)
		require.Len(t, keys, 2)

		// find key1 and key2 in results
		var key1Info, key2Info *KeyInfo
		for i := range keys {
			if keys[i].Key == "key1" {
				key1Info = &keys[i]
			}
			if keys[i].Key == "key2" {
				key2Info = &keys[i]
			}
		}
		require.NotNil(t, key1Info)
		require.NotNil(t, key2Info)

		assert.Equal(t, 5, key1Info.Size)  // len("short")
		assert.Equal(t, 17, key2Info.Size) // len("longer value here")
		assert.Equal(t, "text", key1Info.Format)
		assert.Equal(t, "json", key2Info.Format)
		assert.False(t, key1Info.CreatedAt.IsZero())
		assert.False(t, key1Info.UpdatedAt.IsZero())
	})

	t.Run("ordered by updated_at descending", func(t *testing.T) {
		store2 := newTestStore(t)
		defer store2.Close()

		// create keys with delay to ensure different timestamps
		err := store2.Set("first", []byte("1"), "text")
		require.NoError(t, err)
		time.Sleep(1100 * time.Millisecond) // RFC3339 has second precision
		err = store2.Set("second", []byte("2"), "yaml")
		require.NoError(t, err)

		keys, err := store2.List()
		require.NoError(t, err)
		require.Len(t, keys, 2)

		// most recently updated should be first
		assert.Equal(t, "second", keys[0].Key)
		assert.Equal(t, "first", keys[1].Key)
	})
}

func TestStore_GetInfo(t *testing.T) {
	st := newTestStore(t)
	defer st.Close()

	// create a key
	err := st.Set("testkey", []byte("testvalue"), "json")
	require.NoError(t, err)

	t.Run("returns key info for existing key", func(t *testing.T) {
		info, err := st.GetInfo("testkey")
		require.NoError(t, err)

		assert.Equal(t, "testkey", info.Key)
		assert.Equal(t, 9, info.Size) // len("testvalue")
		assert.Equal(t, "json", info.Format)
		assert.False(t, info.CreatedAt.IsZero())
		assert.False(t, info.UpdatedAt.IsZero())
	})

	t.Run("returns ErrNotFound for nonexistent key", func(t *testing.T) {
		_, err := st.GetInfo("nonexistent")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("updated_at changes on update", func(t *testing.T) {
		info1, err := st.GetInfo("testkey")
		require.NoError(t, err)

		time.Sleep(1100 * time.Millisecond) // ensure timestamp changes
		err = st.Set("testkey", []byte("updated"), "text")
		require.NoError(t, err)

		info2, err := st.GetInfo("testkey")
		require.NoError(t, err)

		assert.True(t, info2.UpdatedAt.After(info1.UpdatedAt), "updated_at should be newer")
		assert.Equal(t, info1.CreatedAt, info2.CreatedAt, "created_at should not change")
	})
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLite(dbPath)
	require.NoError(t, err)
	return store
}

// PostgreSQL tests using testcontainers

func TestStore_Postgres(t *testing.T) {
	ctx := context.Background()

	t.Log("starting postgres container...")
	pgContainer := containers.NewPostgresTestContainerWithDB(ctx, t, "stash_test")
	defer pgContainer.Close(ctx)
	t.Log("postgres container started")

	store, err := New(pgContainer.ConnectionString())
	require.NoError(t, err)
	defer store.Close()

	assert.Equal(t, DBTypePostgres, store.dbType)

	t.Run("set and get value", func(t *testing.T) {
		err := store.Set("pgkey1", []byte("pgvalue1"), "text")
		require.NoError(t, err)

		value, err := store.Get("pgkey1")
		require.NoError(t, err)
		assert.Equal(t, []byte("pgvalue1"), value)
	})

	t.Run("update existing key", func(t *testing.T) {
		err := store.Set("pgkey2", []byte("original"), "text")
		require.NoError(t, err)

		err = store.Set("pgkey2", []byte("updated"), "json")
		require.NoError(t, err)

		value, err := store.Get("pgkey2")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated"), value)
	})

	t.Run("get nonexistent key returns ErrNotFound", func(t *testing.T) {
		_, err := store.Get("nonexistent")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("handles binary data", func(t *testing.T) {
		binary := []byte{0x00, 0x01, 0xFF, 0xFE}
		err := store.Set("pgbinary", binary, "text")
		require.NoError(t, err)

		value, err := store.Get("pgbinary")
		require.NoError(t, err)
		assert.Equal(t, binary, value)
	})

	t.Run("delete existing key", func(t *testing.T) {
		err := store.Set("pgtodelete", []byte("value"), "text")
		require.NoError(t, err)

		err = store.Delete("pgtodelete")
		require.NoError(t, err)

		_, err = store.Get("pgtodelete")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete nonexistent key returns ErrNotFound", func(t *testing.T) {
		err := store.Delete("nonexistent")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("list returns keys with metadata", func(t *testing.T) {
		err := store.Set("pglist1", []byte("short"), "yaml")
		require.NoError(t, err)
		err = store.Set("pglist2", []byte("longer value"), "json")
		require.NoError(t, err)

		keys, err := store.List()
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(keys), 2)

		// find our keys
		var found1, found2 bool
		for _, k := range keys {
			if k.Key == "pglist1" {
				assert.Equal(t, 5, k.Size)
				assert.Equal(t, "yaml", k.Format)
				found1 = true
			}
			if k.Key == "pglist2" {
				assert.Equal(t, 12, k.Size)
				assert.Equal(t, "json", k.Format)
				found2 = true
			}
		}
		assert.True(t, found1, "pglist1 not found")
		assert.True(t, found2, "pglist2 not found")
	})

	t.Run("get info returns correct metadata", func(t *testing.T) {
		err := store.Set("pginfo", []byte("test value"), "json")
		require.NoError(t, err)

		info, err := store.GetInfo("pginfo")
		require.NoError(t, err)
		assert.Equal(t, "pginfo", info.Key)
		assert.Equal(t, 10, info.Size) // len("test value")
		assert.Equal(t, "json", info.Format)
		assert.False(t, info.CreatedAt.IsZero())
		assert.False(t, info.UpdatedAt.IsZero())
	})

	t.Run("set with version succeeds when version matches", func(t *testing.T) {
		err := store.Set("pgversioned", []byte("initial"), "text")
		require.NoError(t, err)

		info, err := store.GetInfo("pgversioned")
		require.NoError(t, err)

		err = store.SetWithVersion("pgversioned", []byte("updated"), "json", info.UpdatedAt)
		require.NoError(t, err)

		value, format, err := store.GetWithFormat("pgversioned")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated"), value)
		assert.Equal(t, "json", format)
	})

	t.Run("set with version fails on conflict", func(t *testing.T) {
		err := store.Set("pgconflict", []byte("original"), "text")
		require.NoError(t, err)

		info1, err := store.GetInfo("pgconflict")
		require.NoError(t, err)

		// simulate concurrent update
		time.Sleep(1100 * time.Millisecond)
		err = store.Set("pgconflict", []byte("concurrent"), "yaml")
		require.NoError(t, err)

		// try update with old version
		err = store.SetWithVersion("pgconflict", []byte("my-update"), "json", info1.UpdatedAt)
		require.ErrorIs(t, err, ErrConflict)

		var conflictErr *ConflictError
		require.ErrorAs(t, err, &conflictErr)
		assert.Equal(t, []byte("concurrent"), conflictErr.Info.CurrentValue)
	})
}

func TestDetectDBType(t *testing.T) {
	tests := []struct {
		url    string
		expect DBType
	}{
		{"stash.db", DBTypeSQLite},
		{"./data/stash.db", DBTypeSQLite},
		{"/tmp/stash.db", DBTypeSQLite},
		{"file:stash.db", DBTypeSQLite},
		{":memory:", DBTypeSQLite},
		{"postgres://user:pass@localhost/db", DBTypePostgres},
		{"postgresql://user:pass@localhost/db", DBTypePostgres},
		{"POSTGRES://USER:PASS@localhost/db", DBTypePostgres},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			assert.Equal(t, tt.expect, detectDBType(tt.url))
		})
	}
}

func TestAdoptQuery(t *testing.T) {
	t.Run("sqlite no changes", func(t *testing.T) {
		s := &Store{dbType: DBTypeSQLite}
		assert.Equal(t, "SELECT * FROM kv WHERE key = ?", s.adoptQuery("SELECT * FROM kv WHERE key = ?"))
		assert.Equal(t, "SELECT length(value) FROM kv", s.adoptQuery("SELECT length(value) FROM kv"))
		assert.Equal(t, "excluded.value", s.adoptQuery("excluded.value"))
	})

	t.Run("postgres converts placeholders", func(t *testing.T) {
		s := &Store{dbType: DBTypePostgres}
		assert.Equal(t, "SELECT * FROM kv WHERE key = $1", s.adoptQuery("SELECT * FROM kv WHERE key = ?"))
		assert.Equal(t, "INSERT INTO kv VALUES ($1, $2, $3)", s.adoptQuery("INSERT INTO kv VALUES (?, ?, ?)"))
	})

	t.Run("postgres converts length to octet_length", func(t *testing.T) {
		s := &Store{dbType: DBTypePostgres}
		assert.Equal(t, "SELECT octet_length(value) FROM kv", s.adoptQuery("SELECT length(value) FROM kv"))
	})

	t.Run("postgres converts excluded to EXCLUDED", func(t *testing.T) {
		s := &Store{dbType: DBTypePostgres}
		assert.Equal(t, "SET value = EXCLUDED.value", s.adoptQuery("SET value = excluded.value"))
	})
}

func TestSQLite_Format(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	t.Run("set with format and get with format", func(t *testing.T) {
		err := store.Set("jsonkey", []byte(`{"key": "value"}`), "json")
		require.NoError(t, err)

		value, format, err := store.GetWithFormat("jsonkey")
		require.NoError(t, err)
		assert.JSONEq(t, `{"key": "value"}`, string(value))
		assert.Equal(t, "json", format)
	})

	t.Run("empty format defaults to text", func(t *testing.T) {
		err := store.Set("defaultkey", []byte("some value"), "")
		require.NoError(t, err)

		value, format, err := store.GetWithFormat("defaultkey")
		require.NoError(t, err)
		assert.Equal(t, []byte("some value"), value)
		assert.Equal(t, "text", format)
	})

	t.Run("format updates when key is updated", func(t *testing.T) {
		err := store.Set("updatekey", []byte("original"), "text")
		require.NoError(t, err)

		_, format, err := store.GetWithFormat("updatekey")
		require.NoError(t, err)
		assert.Equal(t, "text", format)

		err = store.Set("updatekey", []byte(`{"new": "value"}`), "json")
		require.NoError(t, err)

		value, format, err := store.GetWithFormat("updatekey")
		require.NoError(t, err)
		assert.JSONEq(t, `{"new": "value"}`, string(value))
		assert.Equal(t, "json", format)
	})

	t.Run("GetWithFormat returns ErrNotFound for nonexistent key", func(t *testing.T) {
		_, _, err := store.GetWithFormat("nonexistent")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("various formats", func(t *testing.T) {
		formats := []string{"text", "json", "yaml", "xml", "toml", "ini", "shell"}
		for _, fmt := range formats {
			key := "fmt_" + fmt
			err := store.Set(key, []byte("content"), fmt)
			require.NoError(t, err)

			_, gotFmt, err := store.GetWithFormat(key)
			require.NoError(t, err)
			assert.Equal(t, fmt, gotFmt)
		}
	})
}

func TestMigration_SQLite_AddFormatColumn(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")

	// create old schema without format column (simulates pre-migration database)
	db, err := sqlx.Connect("sqlite", dbPath)
	require.NoError(t, err)

	_, err = db.Exec(`
		CREATE TABLE kv (
			key TEXT PRIMARY KEY,
			value BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`)
	require.NoError(t, err)

	// insert data using old schema
	_, err = db.Exec(`INSERT INTO kv (key, value) VALUES (?, ?)`, "legacy-key", []byte("legacy-value"))
	require.NoError(t, err)
	require.NoError(t, db.Close())

	// open with New() - should run migration
	store, err := New(dbPath)
	require.NoError(t, err)
	defer store.Close()

	// verify format column exists and has default value
	value, format, err := store.GetWithFormat("legacy-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("legacy-value"), value)
	assert.Equal(t, "text", format, "migrated row should have default format 'text'")

	// verify new data can be written with format
	err = store.Set("new-key", []byte("new-value"), "json")
	require.NoError(t, err)

	value, format, err = store.GetWithFormat("new-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("new-value"), value)
	assert.Equal(t, "json", format)

	// verify List works with migrated data
	keys, err := store.List()
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}

func TestMigration_SQLite_AlreadyMigrated(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "already-migrated.db")

	// create new schema with format column
	store1, err := New(dbPath)
	require.NoError(t, err)

	err = store1.Set("test-key", []byte("test-value"), "yaml")
	require.NoError(t, err)
	require.NoError(t, store1.Close())

	// open again - migration should be no-op
	store2, err := New(dbPath)
	require.NoError(t, err)
	defer store2.Close()

	value, format, err := store2.GetWithFormat("test-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("test-value"), value)
	assert.Equal(t, "yaml", format)
}

func TestStore_SetWithVersion(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	t.Run("success when version matches", func(t *testing.T) {
		err := store.Set("versioned", []byte("initial"), "text")
		require.NoError(t, err)

		info, err := store.GetInfo("versioned")
		require.NoError(t, err)

		// update with matching version
		err = store.SetWithVersion("versioned", []byte("updated"), "json", info.UpdatedAt)
		require.NoError(t, err)

		// verify update succeeded
		value, format, err := store.GetWithFormat("versioned")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated"), value)
		assert.Equal(t, "json", format)
	})

	t.Run("conflict when version mismatch", func(t *testing.T) {
		err := store.Set("conflict-key", []byte("original"), "text")
		require.NoError(t, err)

		// get initial version
		info1, err := store.GetInfo("conflict-key")
		require.NoError(t, err)

		// simulate concurrent update
		time.Sleep(1100 * time.Millisecond) // ensure timestamp changes
		err = store.Set("conflict-key", []byte("concurrent-update"), "yaml")
		require.NoError(t, err)

		// try to update with old version
		err = store.SetWithVersion("conflict-key", []byte("my-update"), "json", info1.UpdatedAt)
		require.Error(t, err)
		require.ErrorIs(t, err, ErrConflict)

		// verify ConflictError has correct details
		var conflictErr *ConflictError
		require.ErrorAs(t, err, &conflictErr)
		assert.Equal(t, []byte("concurrent-update"), conflictErr.Info.CurrentValue)
		assert.Equal(t, "yaml", conflictErr.Info.CurrentFormat)
		assert.True(t, conflictErr.Info.CurrentVersion.After(info1.UpdatedAt))
		assert.Equal(t, info1.UpdatedAt, conflictErr.Info.AttemptedVersion)
	})

	t.Run("not found when key deleted", func(t *testing.T) {
		err := store.Set("to-delete", []byte("value"), "text")
		require.NoError(t, err)

		info, err := store.GetInfo("to-delete")
		require.NoError(t, err)

		// delete the key
		err = store.Delete("to-delete")
		require.NoError(t, err)

		// try to update deleted key
		err = store.SetWithVersion("to-delete", []byte("update"), "text", info.UpdatedAt)
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("zero time behaves like regular set", func(t *testing.T) {
		// create new key with zero time
		err := store.SetWithVersion("zero-time", []byte("value1"), "text", time.Time{})
		require.NoError(t, err)

		value, err := store.Get("zero-time")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), value)

		// update with zero time (no version check)
		err = store.SetWithVersion("zero-time", []byte("value2"), "json", time.Time{})
		require.NoError(t, err)

		value, format, err := store.GetWithFormat("zero-time")
		require.NoError(t, err)
		assert.Equal(t, []byte("value2"), value)
		assert.Equal(t, "json", format)
	})

	t.Run("empty format defaults to text", func(t *testing.T) {
		err := store.Set("empty-fmt", []byte("val"), "text")
		require.NoError(t, err)

		info, err := store.GetInfo("empty-fmt")
		require.NoError(t, err)

		err = store.SetWithVersion("empty-fmt", []byte("updated"), "", info.UpdatedAt)
		require.NoError(t, err)

		_, format, err := store.GetWithFormat("empty-fmt")
		require.NoError(t, err)
		assert.Equal(t, "text", format)
	})

	t.Run("works with unix nano timestamp round-trip", func(t *testing.T) {
		// this test verifies that nanosecond-precision timestamps survive round-trip
		// through UnixNano() -> time.Unix(0, nanos) conversion (used by web UI)
		err := store.Set("unix-roundtrip", []byte("initial"), "text")
		require.NoError(t, err)

		info, err := store.GetInfo("unix-roundtrip")
		require.NoError(t, err)

		// simulate form round-trip: convert to unix nanos and back (preserves precision)
		unixNanos := info.UpdatedAt.UnixNano()
		reconstructed := time.Unix(0, unixNanos).UTC()

		// update with reconstructed timestamp should succeed
		err = store.SetWithVersion("unix-roundtrip", []byte("updated"), "json", reconstructed)
		require.NoError(t, err, "update with unix-nano-reconstructed timestamp should succeed")

		// verify update worked
		value, format, err := store.GetWithFormat("unix-roundtrip")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated"), value)
		assert.Equal(t, "json", format)
	})
}
