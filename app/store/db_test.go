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
		err := store.Set(t.Context(), "key1", []byte("value1"), "text")
		require.NoError(t, err)

		value, err := store.Get(t.Context(), "key1")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), value)
	})

	t.Run("update existing key", func(t *testing.T) {
		err := store.Set(t.Context(), "key2", []byte("original"), "text")
		require.NoError(t, err)

		err = store.Set(t.Context(), "key2", []byte("updated"), "text")
		require.NoError(t, err)

		value, err := store.Get(t.Context(), "key2")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated"), value)
	})

	t.Run("get nonexistent key returns ErrNotFound", func(t *testing.T) {
		_, err := store.Get(t.Context(), "nonexistent")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("handles binary data", func(t *testing.T) {
		binary := []byte{0x00, 0x01, 0xFF, 0xFE}
		err := store.Set(t.Context(), "binary", binary, "text")
		require.NoError(t, err)

		value, err := store.Get(t.Context(), "binary")
		require.NoError(t, err)
		assert.Equal(t, binary, value)
	})

	t.Run("handles empty value", func(t *testing.T) {
		err := store.Set(t.Context(), "empty", []byte{}, "text")
		require.NoError(t, err)

		value, err := store.Get(t.Context(), "empty")
		require.NoError(t, err)
		assert.Empty(t, value)
	})
}

func TestSQLite_UpdatedAt(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	// set initial value
	err := store.Set(t.Context(), "timekey", []byte("v1"), "text")
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
	err = store.Set(t.Context(), "timekey", []byte("v2"), "text")
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
		err := store.Set(t.Context(), "todelete", []byte("value"), "text")
		require.NoError(t, err)

		err = store.Delete(t.Context(), "todelete")
		require.NoError(t, err)

		_, err = store.Get(t.Context(), "todelete")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete nonexistent key returns ErrNotFound", func(t *testing.T) {
		err := store.Delete(t.Context(), "nonexistent")
		require.ErrorIs(t, err, ErrNotFound)
	})
}

func TestSQLite_List(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	t.Run("empty store returns empty slice", func(t *testing.T) {
		keys, err := store.List(t.Context())
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("returns keys with correct metadata", func(t *testing.T) {
		err := store.Set(t.Context(), "key1", []byte("short"), "text")
		require.NoError(t, err)
		err = store.Set(t.Context(), "key2", []byte("longer value here"), "json")
		require.NoError(t, err)

		keys, err := store.List(t.Context())
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
		err := store2.Set(t.Context(), "first", []byte("1"), "text")
		require.NoError(t, err)
		time.Sleep(1100 * time.Millisecond) // RFC3339 has second precision
		err = store2.Set(t.Context(), "second", []byte("2"), "yaml")
		require.NoError(t, err)

		keys, err := store2.List(t.Context())
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
	err := st.Set(t.Context(), "testkey", []byte("testvalue"), "json")
	require.NoError(t, err)

	t.Run("returns key info for existing key", func(t *testing.T) {
		info, err := st.GetInfo(t.Context(), "testkey")
		require.NoError(t, err)

		assert.Equal(t, "testkey", info.Key)
		assert.Equal(t, 9, info.Size) // len("testvalue")
		assert.Equal(t, "json", info.Format)
		assert.False(t, info.CreatedAt.IsZero())
		assert.False(t, info.UpdatedAt.IsZero())
	})

	t.Run("returns ErrNotFound for nonexistent key", func(t *testing.T) {
		_, err := st.GetInfo(t.Context(), "nonexistent")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("updated_at changes on update", func(t *testing.T) {
		info1, err := st.GetInfo(t.Context(), "testkey")
		require.NoError(t, err)

		time.Sleep(1100 * time.Millisecond) // ensure timestamp changes
		err = st.Set(t.Context(), "testkey", []byte("updated"), "text")
		require.NoError(t, err)

		info2, err := st.GetInfo(t.Context(), "testkey")
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
		err := store.Set(t.Context(), "pgkey1", []byte("pgvalue1"), "text")
		require.NoError(t, err)

		value, err := store.Get(t.Context(), "pgkey1")
		require.NoError(t, err)
		assert.Equal(t, []byte("pgvalue1"), value)
	})

	t.Run("update existing key", func(t *testing.T) {
		err := store.Set(t.Context(), "pgkey2", []byte("original"), "text")
		require.NoError(t, err)

		err = store.Set(t.Context(), "pgkey2", []byte("updated"), "json")
		require.NoError(t, err)

		value, err := store.Get(t.Context(), "pgkey2")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated"), value)
	})

	t.Run("get nonexistent key returns ErrNotFound", func(t *testing.T) {
		_, err := store.Get(t.Context(), "nonexistent")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("handles binary data", func(t *testing.T) {
		binary := []byte{0x00, 0x01, 0xFF, 0xFE}
		err := store.Set(t.Context(), "pgbinary", binary, "text")
		require.NoError(t, err)

		value, err := store.Get(t.Context(), "pgbinary")
		require.NoError(t, err)
		assert.Equal(t, binary, value)
	})

	t.Run("delete existing key", func(t *testing.T) {
		err := store.Set(t.Context(), "pgtodelete", []byte("value"), "text")
		require.NoError(t, err)

		err = store.Delete(t.Context(), "pgtodelete")
		require.NoError(t, err)

		_, err = store.Get(t.Context(), "pgtodelete")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete nonexistent key returns ErrNotFound", func(t *testing.T) {
		err := store.Delete(t.Context(), "nonexistent")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("list returns keys with metadata", func(t *testing.T) {
		err := store.Set(t.Context(), "pglist1", []byte("short"), "yaml")
		require.NoError(t, err)
		err = store.Set(t.Context(), "pglist2", []byte("longer value"), "json")
		require.NoError(t, err)

		keys, err := store.List(t.Context())
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
		err := store.Set(t.Context(), "pginfo", []byte("test value"), "json")
		require.NoError(t, err)

		info, err := store.GetInfo(t.Context(), "pginfo")
		require.NoError(t, err)
		assert.Equal(t, "pginfo", info.Key)
		assert.Equal(t, 10, info.Size) // len("test value")
		assert.Equal(t, "json", info.Format)
		assert.False(t, info.CreatedAt.IsZero())
		assert.False(t, info.UpdatedAt.IsZero())
	})

	t.Run("set with version succeeds when version matches", func(t *testing.T) {
		err := store.Set(t.Context(), "pgversioned", []byte("initial"), "text")
		require.NoError(t, err)

		info, err := store.GetInfo(t.Context(), "pgversioned")
		require.NoError(t, err)

		err = store.SetWithVersion(t.Context(), "pgversioned", []byte("updated"), "json", info.UpdatedAt)
		require.NoError(t, err)

		value, format, err := store.GetWithFormat(t.Context(), "pgversioned")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated"), value)
		assert.Equal(t, "json", format)
	})

	t.Run("set with version fails on conflict", func(t *testing.T) {
		err := store.Set(t.Context(), "pgconflict", []byte("original"), "text")
		require.NoError(t, err)

		info1, err := store.GetInfo(t.Context(), "pgconflict")
		require.NoError(t, err)

		// simulate concurrent update
		time.Sleep(1100 * time.Millisecond)
		err = store.Set(t.Context(), "pgconflict", []byte("concurrent"), "yaml")
		require.NoError(t, err)

		// try update with old version
		err = store.SetWithVersion(t.Context(), "pgconflict", []byte("my-update"), "json", info1.UpdatedAt)
		require.ErrorIs(t, err, ErrConflict)

		var conflictErr *ConflictError
		require.ErrorAs(t, err, &conflictErr)
		assert.Equal(t, []byte("concurrent"), conflictErr.Info.CurrentValue)
	})

	t.Run("session create and get", func(t *testing.T) {
		expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		err := store.CreateSession(t.Context(), "pg-token1", "pguser1", expires)
		require.NoError(t, err)

		username, expiresAt, err := store.GetSession(t.Context(), "pg-token1")
		require.NoError(t, err)
		assert.Equal(t, "pguser1", username)
		assert.Equal(t, expires.Unix(), expiresAt.Unix())
	})

	t.Run("session delete", func(t *testing.T) {
		expires := time.Now().Add(time.Hour).UTC()
		err := store.CreateSession(t.Context(), "pg-token-del", "user", expires)
		require.NoError(t, err)

		err = store.DeleteSession(t.Context(), "pg-token-del")
		require.NoError(t, err)

		_, _, err = store.GetSession(t.Context(), "pg-token-del")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("session delete all", func(t *testing.T) {
		expires := time.Now().Add(time.Hour).UTC()
		_ = store.CreateSession(t.Context(), "pg-all-a", "user", expires)
		_ = store.CreateSession(t.Context(), "pg-all-b", "user", expires)

		err := store.DeleteAllSessions(t.Context())
		require.NoError(t, err)

		_, _, err = store.GetSession(t.Context(), "pg-all-a")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("session delete expired", func(t *testing.T) {
		expired := time.Now().Add(-time.Hour).UTC()
		_ = store.CreateSession(t.Context(), "pg-expired", "user", expired)

		valid := time.Now().Add(time.Hour).UTC()
		_ = store.CreateSession(t.Context(), "pg-valid", "user", valid)

		deleted, err := store.DeleteExpiredSessions(t.Context())
		require.NoError(t, err)
		assert.GreaterOrEqual(t, deleted, int64(1))

		_, _, err = store.GetSession(t.Context(), "pg-expired")
		require.ErrorIs(t, err, ErrNotFound)

		_, _, err = store.GetSession(t.Context(), "pg-valid")
		require.NoError(t, err)
	})

	t.Run("session expiration respects UTC timezone", func(t *testing.T) {
		// store session with explicit UTC time
		expires := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
		err := store.CreateSession(t.Context(), "pg-tz-token", "tzuser", expires)
		require.NoError(t, err)

		// retrieve and verify UTC is preserved
		username, expiresAt, err := store.GetSession(t.Context(), "pg-tz-token")
		require.NoError(t, err)
		assert.Equal(t, "tzuser", username)

		// verify the time instant matches (same point in time)
		assert.Equal(t, expires.Unix(), expiresAt.Unix(), "expiration instant should match")

		// verify the returned time is in UTC location
		assert.Equal(t, "UTC", expiresAt.Location().String(), "returned time should be in UTC")
	})

	t.Run("session delete by username", func(t *testing.T) {
		expires := time.Now().Add(time.Hour).UTC()
		// create sessions for different users
		_ = store.CreateSession(t.Context(), "pg-alice-1", "alice", expires)
		_ = store.CreateSession(t.Context(), "pg-alice-2", "alice", expires)
		_ = store.CreateSession(t.Context(), "pg-bob-1", "bob", expires)

		// delete alice's sessions only
		err := store.DeleteSessionsByUsername(t.Context(), "alice")
		require.NoError(t, err)

		// alice's sessions should be gone
		_, _, err = store.GetSession(t.Context(), "pg-alice-1")
		require.ErrorIs(t, err, ErrNotFound)
		_, _, err = store.GetSession(t.Context(), "pg-alice-2")
		require.ErrorIs(t, err, ErrNotFound)

		// bob's session should remain
		username, _, err := store.GetSession(t.Context(), "pg-bob-1")
		require.NoError(t, err)
		assert.Equal(t, "bob", username)
	})

	t.Run("session delete by username - no sessions", func(t *testing.T) {
		// should not error when user has no sessions
		err := store.DeleteSessionsByUsername(t.Context(), "pg-nonexistent-user")
		require.NoError(t, err)
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
		err := store.Set(t.Context(), "jsonkey", []byte(`{"key": "value"}`), "json")
		require.NoError(t, err)

		value, format, err := store.GetWithFormat(t.Context(), "jsonkey")
		require.NoError(t, err)
		assert.JSONEq(t, `{"key": "value"}`, string(value))
		assert.Equal(t, "json", format)
	})

	t.Run("empty format defaults to text", func(t *testing.T) {
		err := store.Set(t.Context(), "defaultkey", []byte("some value"), "")
		require.NoError(t, err)

		value, format, err := store.GetWithFormat(t.Context(), "defaultkey")
		require.NoError(t, err)
		assert.Equal(t, []byte("some value"), value)
		assert.Equal(t, "text", format)
	})

	t.Run("format updates when key is updated", func(t *testing.T) {
		err := store.Set(t.Context(), "updatekey", []byte("original"), "text")
		require.NoError(t, err)

		_, format, err := store.GetWithFormat(t.Context(), "updatekey")
		require.NoError(t, err)
		assert.Equal(t, "text", format)

		err = store.Set(t.Context(), "updatekey", []byte(`{"new": "value"}`), "json")
		require.NoError(t, err)

		value, format, err := store.GetWithFormat(t.Context(), "updatekey")
		require.NoError(t, err)
		assert.JSONEq(t, `{"new": "value"}`, string(value))
		assert.Equal(t, "json", format)
	})

	t.Run("GetWithFormat returns ErrNotFound for nonexistent key", func(t *testing.T) {
		_, _, err := store.GetWithFormat(t.Context(), "nonexistent")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("various formats", func(t *testing.T) {
		formats := []string{"text", "json", "yaml", "xml", "toml", "ini", "shell"}
		for _, fmt := range formats {
			key := "fmt_" + fmt
			err := store.Set(t.Context(), key, []byte("content"), fmt)
			require.NoError(t, err)

			_, gotFmt, err := store.GetWithFormat(t.Context(), key)
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
	value, format, err := store.GetWithFormat(t.Context(), "legacy-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("legacy-value"), value)
	assert.Equal(t, "text", format, "migrated row should have default format 'text'")

	// verify new data can be written with format
	err = store.Set(t.Context(), "new-key", []byte("new-value"), "json")
	require.NoError(t, err)

	value, format, err = store.GetWithFormat(t.Context(), "new-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("new-value"), value)
	assert.Equal(t, "json", format)

	// verify List works with migrated data
	keys, err := store.List(t.Context())
	require.NoError(t, err)
	assert.Len(t, keys, 2)
}

func TestMigration_SQLite_AlreadyMigrated(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "already-migrated.db")

	// create new schema with format column
	store1, err := New(dbPath)
	require.NoError(t, err)

	err = store1.Set(t.Context(), "test-key", []byte("test-value"), "yaml")
	require.NoError(t, err)
	require.NoError(t, store1.Close())

	// open again - migration should be no-op
	store2, err := New(dbPath)
	require.NoError(t, err)
	defer store2.Close()

	value, format, err := store2.GetWithFormat(t.Context(), "test-key")
	require.NoError(t, err)
	assert.Equal(t, []byte("test-value"), value)
	assert.Equal(t, "yaml", format)
}

func TestStore_SetWithVersion(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	t.Run("success when version matches", func(t *testing.T) {
		err := store.Set(t.Context(), "versioned", []byte("initial"), "text")
		require.NoError(t, err)

		info, err := store.GetInfo(t.Context(), "versioned")
		require.NoError(t, err)

		// update with matching version
		err = store.SetWithVersion(t.Context(), "versioned", []byte("updated"), "json", info.UpdatedAt)
		require.NoError(t, err)

		// verify update succeeded
		value, format, err := store.GetWithFormat(t.Context(), "versioned")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated"), value)
		assert.Equal(t, "json", format)
	})

	t.Run("conflict when version mismatch", func(t *testing.T) {
		err := store.Set(t.Context(), "conflict-key", []byte("original"), "text")
		require.NoError(t, err)

		// get initial version
		info1, err := store.GetInfo(t.Context(), "conflict-key")
		require.NoError(t, err)

		// simulate concurrent update
		time.Sleep(1100 * time.Millisecond) // ensure timestamp changes
		err = store.Set(t.Context(), "conflict-key", []byte("concurrent-update"), "yaml")
		require.NoError(t, err)

		// try to update with old version
		err = store.SetWithVersion(t.Context(), "conflict-key", []byte("my-update"), "json", info1.UpdatedAt)
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
		err := store.Set(t.Context(), "to-delete", []byte("value"), "text")
		require.NoError(t, err)

		info, err := store.GetInfo(t.Context(), "to-delete")
		require.NoError(t, err)

		// delete the key
		err = store.Delete(t.Context(), "to-delete")
		require.NoError(t, err)

		// try to update deleted key
		err = store.SetWithVersion(t.Context(), "to-delete", []byte("update"), "text", info.UpdatedAt)
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("zero time behaves like regular set", func(t *testing.T) {
		// create new key with zero time
		err := store.SetWithVersion(t.Context(), "zero-time", []byte("value1"), "text", time.Time{})
		require.NoError(t, err)

		value, err := store.Get(t.Context(), "zero-time")
		require.NoError(t, err)
		assert.Equal(t, []byte("value1"), value)

		// update with zero time (no version check)
		err = store.SetWithVersion(t.Context(), "zero-time", []byte("value2"), "json", time.Time{})
		require.NoError(t, err)

		value, format, err := store.GetWithFormat(t.Context(), "zero-time")
		require.NoError(t, err)
		assert.Equal(t, []byte("value2"), value)
		assert.Equal(t, "json", format)
	})

	t.Run("empty format defaults to text", func(t *testing.T) {
		err := store.Set(t.Context(), "empty-fmt", []byte("val"), "text")
		require.NoError(t, err)

		info, err := store.GetInfo(t.Context(), "empty-fmt")
		require.NoError(t, err)

		err = store.SetWithVersion(t.Context(), "empty-fmt", []byte("updated"), "", info.UpdatedAt)
		require.NoError(t, err)

		_, format, err := store.GetWithFormat(t.Context(), "empty-fmt")
		require.NoError(t, err)
		assert.Equal(t, "text", format)
	})

	t.Run("works with unix nano timestamp round-trip", func(t *testing.T) {
		// this test verifies that nanosecond-precision timestamps survive round-trip
		// through UnixNano() -> time.Unix(0, nanos) conversion (used by web UI)
		err := store.Set(t.Context(), "unix-roundtrip", []byte("initial"), "text")
		require.NoError(t, err)

		info, err := store.GetInfo(t.Context(), "unix-roundtrip")
		require.NoError(t, err)

		// simulate form round-trip: convert to unix nanos and back (preserves precision)
		unixNanos := info.UpdatedAt.UnixNano()
		reconstructed := time.Unix(0, unixNanos).UTC()

		// update with reconstructed timestamp should succeed
		err = store.SetWithVersion(t.Context(), "unix-roundtrip", []byte("updated"), "json", reconstructed)
		require.NoError(t, err, "update with unix-nano-reconstructed timestamp should succeed")

		// verify update worked
		value, format, err := store.GetWithFormat(t.Context(), "unix-roundtrip")
		require.NoError(t, err)
		assert.Equal(t, []byte("updated"), value)
		assert.Equal(t, "json", format)
	})
}

func TestSQLite_Session(t *testing.T) {
	store := newTestStore(t)
	ctx := t.Context()

	t.Run("create and get session", func(t *testing.T) {
		expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
		err := store.CreateSession(ctx, "token1", "user1", expires)
		require.NoError(t, err)

		username, expiresAt, err := store.GetSession(ctx, "token1")
		require.NoError(t, err)
		assert.Equal(t, "user1", username)
		assert.Equal(t, expires.Unix(), expiresAt.Unix())
	})

	t.Run("get nonexistent session", func(t *testing.T) {
		_, _, err := store.GetSession(ctx, "nonexistent")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete session", func(t *testing.T) {
		expires := time.Now().Add(time.Hour).UTC()
		err := store.CreateSession(ctx, "token-delete", "user", expires)
		require.NoError(t, err)

		err = store.DeleteSession(ctx, "token-delete")
		require.NoError(t, err)

		_, _, err = store.GetSession(ctx, "token-delete")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete all sessions", func(t *testing.T) {
		expires := time.Now().Add(time.Hour).UTC()
		_ = store.CreateSession(ctx, "token-a", "user", expires)
		_ = store.CreateSession(ctx, "token-b", "user", expires)

		err := store.DeleteAllSessions(ctx)
		require.NoError(t, err)

		_, _, err = store.GetSession(ctx, "token-a")
		require.ErrorIs(t, err, ErrNotFound)
		_, _, err = store.GetSession(ctx, "token-b")
		require.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete expired sessions", func(t *testing.T) {
		// create expired session
		expired := time.Now().Add(-time.Hour).UTC()
		_ = store.CreateSession(ctx, "expired-token", "user", expired)

		// create valid session
		valid := time.Now().Add(time.Hour).UTC()
		_ = store.CreateSession(ctx, "valid-token", "user", valid)

		deleted, err := store.DeleteExpiredSessions(ctx)
		require.NoError(t, err)
		assert.Equal(t, int64(1), deleted)

		// expired should be gone
		_, _, err = store.GetSession(ctx, "expired-token")
		require.ErrorIs(t, err, ErrNotFound)

		// valid should remain
		_, _, err = store.GetSession(ctx, "valid-token")
		require.NoError(t, err)
	})

	t.Run("duplicate token replaces session", func(t *testing.T) {
		expires := time.Now().Add(time.Hour).UTC()
		err := store.CreateSession(ctx, "dup-token", "user1", expires)
		require.NoError(t, err)

		err = store.CreateSession(ctx, "dup-token", "user2", expires)
		require.NoError(t, err)

		username, _, err := store.GetSession(ctx, "dup-token")
		require.NoError(t, err)
		assert.Equal(t, "user2", username)
	})

	t.Run("session expiration respects UTC timezone", func(t *testing.T) {
		// store session with explicit UTC time
		expires := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
		err := store.CreateSession(ctx, "tz-token", "tzuser", expires)
		require.NoError(t, err)

		// retrieve and verify UTC is preserved
		username, expiresAt, err := store.GetSession(ctx, "tz-token")
		require.NoError(t, err)
		assert.Equal(t, "tzuser", username)

		// verify the time instant matches (same point in time)
		assert.Equal(t, expires.Unix(), expiresAt.Unix(), "expiration instant should match")

		// verify the returned time is in UTC location
		assert.Equal(t, "UTC", expiresAt.Location().String(), "returned time should be in UTC")
	})

	t.Run("delete sessions by username", func(t *testing.T) {
		expires := time.Now().Add(time.Hour).UTC()
		// create sessions for different users
		err := store.CreateSession(ctx, "token-alice-1", "alice", expires)
		require.NoError(t, err)
		err = store.CreateSession(ctx, "token-alice-2", "alice", expires)
		require.NoError(t, err)
		err = store.CreateSession(ctx, "token-bob-1", "bob", expires)
		require.NoError(t, err)

		// delete alice's sessions only
		err = store.DeleteSessionsByUsername(ctx, "alice")
		require.NoError(t, err)

		// alice's sessions should be gone
		_, _, err = store.GetSession(ctx, "token-alice-1")
		require.ErrorIs(t, err, ErrNotFound)
		_, _, err = store.GetSession(ctx, "token-alice-2")
		require.ErrorIs(t, err, ErrNotFound)

		// bob's session should remain
		username, _, err := store.GetSession(ctx, "token-bob-1")
		require.NoError(t, err)
		assert.Equal(t, "bob", username)
	})

	t.Run("delete sessions by username - no sessions", func(t *testing.T) {
		// should not error when user has no sessions
		err := store.DeleteSessionsByUsername(ctx, "nonexistent-user")
		require.NoError(t, err)
	})
}
