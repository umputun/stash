package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-pkgz/testutils/containers"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/enum"
)

// pgConnString is set by TestMain; read-only after initialization.
var pgConnString string

var testEngines = []string{"sqlite", "postgres"}

func newTestStore(t *testing.T, engine string, opts ...Option) *Store {
	t.Helper()
	var connStr string
	switch engine {
	case "sqlite":
		connStr = filepath.Join(t.TempDir(), "test.db")
	case "postgres":
		connStr = pgConnString
	default:
		t.Fatalf("unknown engine: %s", engine)
	}
	store, err := New(connStr, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestMain(m *testing.M) {
	ctx := context.Background()

	pgContainer, err := containers.NewPostgresTestContainerWithDBE(ctx, "stash_test")
	if err != nil {
		panic("failed to start postgres container: " + err.Error())
	}

	pgConnString = pgContainer.ConnectionString()

	code := m.Run()

	if err := pgContainer.Close(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "failed to close postgres container: %v\n", err)
	}
	os.Exit(code)
}

func TestNew(t *testing.T) {
	t.Run("creates database successfully", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "test.db")
		store, err := New(dbPath)
		require.NoError(t, err)
		defer store.Close()
		assert.NotNil(t, store.db)
	})

	t.Run("fails with invalid path", func(t *testing.T) {
		_, err := New("/nonexistent/dir/test.db")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to connect")
	})
}

func TestStore_SetGet(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStore(t, engine)

			t.Run("set and get value", func(t *testing.T) {
				_, err := store.Set(t.Context(), "key1", []byte("value1"), "text")
				require.NoError(t, err)

				value, err := store.Get(t.Context(), "key1")
				require.NoError(t, err)
				assert.Equal(t, []byte("value1"), value)
			})

			t.Run("update existing key", func(t *testing.T) {
				_, err := store.Set(t.Context(), "key2", []byte("original"), "text")
				require.NoError(t, err)

				_, err = store.Set(t.Context(), "key2", []byte("updated"), "text")
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
				_, err := store.Set(t.Context(), "binary", binary, "text")
				require.NoError(t, err)

				value, err := store.Get(t.Context(), "binary")
				require.NoError(t, err)
				assert.Equal(t, binary, value)
			})

			t.Run("handles empty value", func(t *testing.T) {
				_, err := store.Set(t.Context(), "empty", []byte{}, "text")
				require.NoError(t, err)

				value, err := store.Get(t.Context(), "empty")
				require.NoError(t, err)
				assert.Empty(t, value)
			})
		})
	}
}

func TestStore_UpdatedAt(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStore(t, engine)

			// set initial value
			_, err := store.Set(t.Context(), "timekey", []byte("v1"), "text")
			require.NoError(t, err)

			// get created_at
			var created, updated1 string
			err = store.db.Get(&created, store.adoptQuery("SELECT created_at FROM kv WHERE key = ?"), "timekey")
			require.NoError(t, err)
			err = store.db.Get(&updated1, store.adoptQuery("SELECT updated_at FROM kv WHERE key = ?"), "timekey")
			require.NoError(t, err)
			assert.Equal(t, created, updated1, "created_at and updated_at should match on insert")

			// update value (wait to ensure different timestamp - RFC3339 has second precision)
			time.Sleep(1100 * time.Millisecond)
			_, err = store.Set(t.Context(), "timekey", []byte("v2"), "text")
			require.NoError(t, err)

			// verify updated_at changed but created_at didn't
			var created2, updated2 string
			err = store.db.Get(&created2, store.adoptQuery("SELECT created_at FROM kv WHERE key = ?"), "timekey")
			require.NoError(t, err)
			err = store.db.Get(&updated2, store.adoptQuery("SELECT updated_at FROM kv WHERE key = ?"), "timekey")
			require.NoError(t, err)

			assert.Equal(t, created, created2, "created_at should not change on update")
			assert.NotEqual(t, updated1, updated2, "updated_at should change on update")
		})
	}
}

func TestStore_Delete(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStore(t, engine)

			t.Run("delete existing key", func(t *testing.T) {
				_, err := store.Set(t.Context(), "todelete", []byte("value"), "text")
				require.NoError(t, err)

				err = store.Delete(t.Context(), "todelete")
				require.NoError(t, err)

				_, err = store.Get(t.Context(), "todelete")
				require.ErrorIs(t, err, ErrNotFound)
			})

			t.Run("delete nonexistent key returns ErrNotFound", func(t *testing.T) {
				err := store.Delete(t.Context(), "nonexistent-del")
				require.ErrorIs(t, err, ErrNotFound)
			})
		})
	}
}

func TestStore_List(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStore(t, engine)

			t.Run("returns keys with correct metadata", func(t *testing.T) {
				_, err := store.Set(t.Context(), "list/key1", []byte("short"), "text")
				require.NoError(t, err)
				_, err = store.Set(t.Context(), "list/key2", []byte("longer value here"), "json")
				require.NoError(t, err)

				keys, err := store.List(t.Context(), enum.SecretsFilterAll)
				require.NoError(t, err)

				// find our keys in results (postgres may have other keys from parallel tests)
				var key1Info, key2Info *KeyInfo
				for i := range keys {
					if keys[i].Key == "list/key1" {
						key1Info = &keys[i]
					}
					if keys[i].Key == "list/key2" {
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
				// use unique prefix to avoid conflicts with other tests
				prefix := "list-order/" + engine + "/"

				// create keys with delay to ensure different timestamps
				_, err := store.Set(t.Context(), prefix+"first", []byte("1"), "text")
				require.NoError(t, err)
				time.Sleep(1100 * time.Millisecond) // RFC3339 has second precision
				_, err = store.Set(t.Context(), prefix+"second", []byte("2"), "yaml")
				require.NoError(t, err)

				keys, err := store.List(t.Context(), enum.SecretsFilterAll)
				require.NoError(t, err)

				// find our keys and check their relative order
				var firstIdx, secondIdx = -1, -1
				for i, k := range keys {
					if k.Key == prefix+"first" {
						firstIdx = i
					}
					if k.Key == prefix+"second" {
						secondIdx = i
					}
				}
				require.NotEqual(t, -1, firstIdx, "first key not found")
				require.NotEqual(t, -1, secondIdx, "second key not found")

				// most recently updated should come before older (lower index = earlier in list)
				assert.Less(t, secondIdx, firstIdx, "second (newer) should come before first (older)")
			})
		})
	}
}

func TestStore_GetInfo(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			st := newTestStore(t, engine)

			// create a key
			_, err := st.Set(t.Context(), "info/testkey", []byte("testvalue"), "json")
			require.NoError(t, err)

			t.Run("returns key info for existing key", func(t *testing.T) {
				info, err := st.GetInfo(t.Context(), "info/testkey")
				require.NoError(t, err)

				assert.Equal(t, "info/testkey", info.Key)
				assert.Equal(t, 9, info.Size) // len("testvalue")
				assert.Equal(t, "json", info.Format)
				assert.False(t, info.CreatedAt.IsZero())
				assert.False(t, info.UpdatedAt.IsZero())
			})

			t.Run("returns ErrNotFound for nonexistent key", func(t *testing.T) {
				_, err := st.GetInfo(t.Context(), "nonexistent-info")
				assert.ErrorIs(t, err, ErrNotFound)
			})

			t.Run("updated_at changes on update", func(t *testing.T) {
				info1, err := st.GetInfo(t.Context(), "info/testkey")
				require.NoError(t, err)

				time.Sleep(1100 * time.Millisecond) // ensure timestamp changes
				_, err = st.Set(t.Context(), "info/testkey", []byte("updated"), "text")
				require.NoError(t, err)

				info2, err := st.GetInfo(t.Context(), "info/testkey")
				require.NoError(t, err)

				assert.True(t, info2.UpdatedAt.After(info1.UpdatedAt), "updated_at should be newer")
				assert.Equal(t, info1.CreatedAt, info2.CreatedAt, "created_at should not change")
			})
		})
	}
}

func TestStore_ZKEncrypted(t *testing.T) {
	// create valid ZK payload
	zk, err := NewZKCrypto([]byte("test-passphrase-min-16"))
	require.NoError(t, err)
	zkValue, err := zk.Encrypt([]byte("encrypted-data"))
	require.NoError(t, err)

	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			st := newTestStore(t, engine)

			// create a regular key and a ZK-encrypted key
			_, err := st.Set(t.Context(), "zk/regular", []byte("plain value"), "text")
			require.NoError(t, err)
			_, err = st.Set(t.Context(), "zk/encrypted", zkValue, "text")
			require.NoError(t, err)

			t.Run("GetInfo returns ZKEncrypted=true for $ZK$ values", func(t *testing.T) {
				info, err := st.GetInfo(t.Context(), "zk/encrypted")
				require.NoError(t, err)
				assert.True(t, info.ZKEncrypted, "ZKEncrypted should be true for $ZK$ prefix")
			})

			t.Run("GetInfo returns ZKEncrypted=false for regular values", func(t *testing.T) {
				info, err := st.GetInfo(t.Context(), "zk/regular")
				require.NoError(t, err)
				assert.False(t, info.ZKEncrypted, "ZKEncrypted should be false for regular values")
			})

			t.Run("List returns ZKEncrypted flag correctly", func(t *testing.T) {
				keys, err := st.List(t.Context(), enum.SecretsFilterAll)
				require.NoError(t, err)

				var regularInfo, encryptedInfo *KeyInfo
				for i := range keys {
					if keys[i].Key == "zk/regular" {
						regularInfo = &keys[i]
					}
					if keys[i].Key == "zk/encrypted" {
						encryptedInfo = &keys[i]
					}
				}
				require.NotNil(t, regularInfo, "regular key not found")
				require.NotNil(t, encryptedInfo, "encrypted key not found")

				assert.False(t, regularInfo.ZKEncrypted, "ZKEncrypted should be false for regular key")
				assert.True(t, encryptedInfo.ZKEncrypted, "ZKEncrypted should be true for $ZK$ key")
			})
		})
	}
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

func TestStore_Format(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStore(t, engine)

			t.Run("set with format and get with format", func(t *testing.T) {
				_, err := store.Set(t.Context(), "fmt/jsonkey", []byte(`{"key": "value"}`), "json")
				require.NoError(t, err)

				value, format, err := store.GetWithFormat(t.Context(), "fmt/jsonkey")
				require.NoError(t, err)
				assert.JSONEq(t, `{"key": "value"}`, string(value))
				assert.Equal(t, "json", format)
			})

			t.Run("empty format defaults to text", func(t *testing.T) {
				_, err := store.Set(t.Context(), "fmt/defaultkey", []byte("some value"), "")
				require.NoError(t, err)

				value, format, err := store.GetWithFormat(t.Context(), "fmt/defaultkey")
				require.NoError(t, err)
				assert.Equal(t, []byte("some value"), value)
				assert.Equal(t, "text", format)
			})

			t.Run("format updates when key is updated", func(t *testing.T) {
				_, err := store.Set(t.Context(), "fmt/updatekey", []byte("original"), "text")
				require.NoError(t, err)

				_, format, err := store.GetWithFormat(t.Context(), "fmt/updatekey")
				require.NoError(t, err)
				assert.Equal(t, "text", format)

				_, err = store.Set(t.Context(), "fmt/updatekey", []byte(`{"new": "value"}`), "json")
				require.NoError(t, err)

				value, format, err := store.GetWithFormat(t.Context(), "fmt/updatekey")
				require.NoError(t, err)
				assert.JSONEq(t, `{"new": "value"}`, string(value))
				assert.Equal(t, "json", format)
			})

			t.Run("GetWithFormat returns ErrNotFound for nonexistent key", func(t *testing.T) {
				_, _, err := store.GetWithFormat(t.Context(), "nonexistent-fmt")
				require.ErrorIs(t, err, ErrNotFound)
			})

			t.Run("various formats", func(t *testing.T) {
				formats := []string{"text", "json", "yaml", "xml", "toml", "ini", "shell"}
				for _, fmt := range formats {
					key := "fmt/various_" + engine + "_" + fmt
					_, err := store.Set(t.Context(), key, []byte("content"), fmt)
					require.NoError(t, err)

					_, gotFmt, err := store.GetWithFormat(t.Context(), key)
					require.NoError(t, err)
					assert.Equal(t, fmt, gotFmt)
				}
			})
		})
	}
}

func TestStore_Migration(t *testing.T) {
	t.Run("sqlite/add format column", func(t *testing.T) {
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
		_, err = store.Set(t.Context(), "new-key", []byte("new-value"), "json")
		require.NoError(t, err)

		value, format, err = store.GetWithFormat(t.Context(), "new-key")
		require.NoError(t, err)
		assert.Equal(t, []byte("new-value"), value)
		assert.Equal(t, "json", format)

		// verify List works with migrated data
		keys, err := store.List(t.Context(), enum.SecretsFilterAll)
		require.NoError(t, err)
		assert.Len(t, keys, 2)
	})

	t.Run("sqlite/already migrated", func(t *testing.T) {
		dbPath := filepath.Join(t.TempDir(), "already-migrated.db")

		// create new schema with format column
		store1, err := New(dbPath)
		require.NoError(t, err)

		_, err = store1.Set(t.Context(), "test-key", []byte("test-value"), "yaml")
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
	})
}

func TestStore_SetWithVersion(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStore(t, engine)

			t.Run("success when version matches", func(t *testing.T) {
				_, err := store.Set(t.Context(), "ver/versioned", []byte("initial"), "text")
				require.NoError(t, err)

				info, err := store.GetInfo(t.Context(), "ver/versioned")
				require.NoError(t, err)

				// update with matching version
				err = store.SetWithVersion(t.Context(), "ver/versioned", []byte("updated"), "json", info.UpdatedAt)
				require.NoError(t, err)

				// verify update succeeded
				value, format, err := store.GetWithFormat(t.Context(), "ver/versioned")
				require.NoError(t, err)
				assert.Equal(t, []byte("updated"), value)
				assert.Equal(t, "json", format)
			})

			t.Run("conflict when version mismatch", func(t *testing.T) {
				_, err := store.Set(t.Context(), "ver/conflict-key", []byte("original"), "text")
				require.NoError(t, err)

				// get initial version
				info1, err := store.GetInfo(t.Context(), "ver/conflict-key")
				require.NoError(t, err)

				// simulate concurrent update
				time.Sleep(1100 * time.Millisecond) // ensure timestamp changes
				_, err = store.Set(t.Context(), "ver/conflict-key", []byte("concurrent-update"), "yaml")
				require.NoError(t, err)

				// try to update with old version
				err = store.SetWithVersion(t.Context(), "ver/conflict-key", []byte("my-update"), "json", info1.UpdatedAt)
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
				_, err := store.Set(t.Context(), "ver/to-delete", []byte("value"), "text")
				require.NoError(t, err)

				info, err := store.GetInfo(t.Context(), "ver/to-delete")
				require.NoError(t, err)

				// delete the key
				err = store.Delete(t.Context(), "ver/to-delete")
				require.NoError(t, err)

				// try to update deleted key
				err = store.SetWithVersion(t.Context(), "ver/to-delete", []byte("update"), "text", info.UpdatedAt)
				require.ErrorIs(t, err, ErrNotFound)
			})

			t.Run("zero time behaves like regular set", func(t *testing.T) {
				// create new key with zero time
				err := store.SetWithVersion(t.Context(), "ver/zero-time", []byte("value1"), "text", time.Time{})
				require.NoError(t, err)

				value, err := store.Get(t.Context(), "ver/zero-time")
				require.NoError(t, err)
				assert.Equal(t, []byte("value1"), value)

				// update with zero time (no version check)
				err = store.SetWithVersion(t.Context(), "ver/zero-time", []byte("value2"), "json", time.Time{})
				require.NoError(t, err)

				value, format, err := store.GetWithFormat(t.Context(), "ver/zero-time")
				require.NoError(t, err)
				assert.Equal(t, []byte("value2"), value)
				assert.Equal(t, "json", format)
			})

			t.Run("empty format defaults to text", func(t *testing.T) {
				_, err := store.Set(t.Context(), "ver/empty-fmt", []byte("val"), "text")
				require.NoError(t, err)

				info, err := store.GetInfo(t.Context(), "ver/empty-fmt")
				require.NoError(t, err)

				err = store.SetWithVersion(t.Context(), "ver/empty-fmt", []byte("updated"), "", info.UpdatedAt)
				require.NoError(t, err)

				_, format, err := store.GetWithFormat(t.Context(), "ver/empty-fmt")
				require.NoError(t, err)
				assert.Equal(t, "text", format)
			})

			t.Run("works with unix nano timestamp round-trip", func(t *testing.T) {
				// this test verifies that nanosecond-precision timestamps survive round-trip
				// through UnixNano() -> time.Unix(0, nanos) conversion (used by web UI)
				_, err := store.Set(t.Context(), "ver/unix-roundtrip", []byte("initial"), "text")
				require.NoError(t, err)

				info, err := store.GetInfo(t.Context(), "ver/unix-roundtrip")
				require.NoError(t, err)

				// simulate form round-trip: convert to unix nanos and back (preserves precision)
				unixNanos := info.UpdatedAt.UnixNano()
				reconstructed := time.Unix(0, unixNanos).UTC()

				// update with reconstructed timestamp should succeed
				err = store.SetWithVersion(t.Context(), "ver/unix-roundtrip", []byte("updated"), "json", reconstructed)
				require.NoError(t, err, "update with unix-nano-reconstructed timestamp should succeed")

				// verify update worked
				value, format, err := store.GetWithFormat(t.Context(), "ver/unix-roundtrip")
				require.NoError(t, err)
				assert.Equal(t, []byte("updated"), value)
				assert.Equal(t, "json", format)
			})
		})
	}
}

func TestStore_Session(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStore(t, engine)
			ctx := t.Context()
			prefix := "sess/" + engine + "/"

			t.Run("create and get session", func(t *testing.T) {
				expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
				err := store.CreateSession(ctx, prefix+"token1", "user1", expires)
				require.NoError(t, err)

				username, expiresAt, err := store.GetSession(ctx, prefix+"token1")
				require.NoError(t, err)
				assert.Equal(t, "user1", username)
				assert.Equal(t, expires.Unix(), expiresAt.Unix())
			})

			t.Run("get nonexistent session", func(t *testing.T) {
				_, _, err := store.GetSession(ctx, prefix+"nonexistent")
				require.ErrorIs(t, err, ErrNotFound)
			})

			t.Run("delete session", func(t *testing.T) {
				expires := time.Now().Add(time.Hour).UTC()
				err := store.CreateSession(ctx, prefix+"token-delete", "user", expires)
				require.NoError(t, err)

				err = store.DeleteSession(ctx, prefix+"token-delete")
				require.NoError(t, err)

				_, _, err = store.GetSession(ctx, prefix+"token-delete")
				require.ErrorIs(t, err, ErrNotFound)
			})

			t.Run("delete all sessions", func(t *testing.T) {
				expires := time.Now().Add(time.Hour).UTC()
				err := store.CreateSession(ctx, prefix+"token-a", "user", expires)
				require.NoError(t, err)
				err = store.CreateSession(ctx, prefix+"token-b", "user", expires)
				require.NoError(t, err)

				err = store.DeleteAllSessions(ctx)
				require.NoError(t, err)

				_, _, err = store.GetSession(ctx, prefix+"token-a")
				require.ErrorIs(t, err, ErrNotFound)
				_, _, err = store.GetSession(ctx, prefix+"token-b")
				require.ErrorIs(t, err, ErrNotFound)
			})

			t.Run("delete expired sessions", func(t *testing.T) {
				// create expired session
				expired := time.Now().Add(-time.Hour).UTC()
				err := store.CreateSession(ctx, prefix+"expired-token", "user", expired)
				require.NoError(t, err)

				// create valid session
				valid := time.Now().Add(time.Hour).UTC()
				err = store.CreateSession(ctx, prefix+"valid-token", "user", valid)
				require.NoError(t, err)

				deleted, err := store.DeleteExpiredSessions(ctx)
				require.NoError(t, err)
				assert.Positive(t, deleted)

				// expired should be gone
				_, _, err = store.GetSession(ctx, prefix+"expired-token")
				require.ErrorIs(t, err, ErrNotFound)

				// valid should remain
				_, _, err = store.GetSession(ctx, prefix+"valid-token")
				require.NoError(t, err)
			})

			t.Run("duplicate token replaces session", func(t *testing.T) {
				expires := time.Now().Add(time.Hour).UTC()
				err := store.CreateSession(ctx, prefix+"dup-token", "user1", expires)
				require.NoError(t, err)

				err = store.CreateSession(ctx, prefix+"dup-token", "user2", expires)
				require.NoError(t, err)

				username, _, err := store.GetSession(ctx, prefix+"dup-token")
				require.NoError(t, err)
				assert.Equal(t, "user2", username)
			})

			t.Run("session expiration respects UTC timezone", func(t *testing.T) {
				// store session with explicit UTC time
				expires := time.Now().Add(30 * time.Minute).UTC().Truncate(time.Second)
				err := store.CreateSession(ctx, prefix+"tz-token", "tzuser", expires)
				require.NoError(t, err)

				// retrieve and verify UTC is preserved
				username, expiresAt, err := store.GetSession(ctx, prefix+"tz-token")
				require.NoError(t, err)
				assert.Equal(t, "tzuser", username)

				// verify the time instant matches (same point in time)
				assert.Equal(t, expires.Unix(), expiresAt.Unix(), "expiration instant should match")

				// verify the returned time is in UTC location
				assert.Equal(t, "UTC", expiresAt.Location().String(), "returned time should be in UTC")
			})

			t.Run("delete sessions by username", func(t *testing.T) {
				expires := time.Now().Add(time.Hour).UTC()
				aliceUser := prefix + "alice"
				bobUser := prefix + "bob"
				// create sessions for different users
				err := store.CreateSession(ctx, prefix+"token-alice-1", aliceUser, expires)
				require.NoError(t, err)
				err = store.CreateSession(ctx, prefix+"token-alice-2", aliceUser, expires)
				require.NoError(t, err)
				err = store.CreateSession(ctx, prefix+"token-bob-1", bobUser, expires)
				require.NoError(t, err)

				// delete alice's sessions only
				err = store.DeleteSessionsByUsername(ctx, aliceUser)
				require.NoError(t, err)

				// alice's sessions should be gone
				_, _, err = store.GetSession(ctx, prefix+"token-alice-1")
				require.ErrorIs(t, err, ErrNotFound)
				_, _, err = store.GetSession(ctx, prefix+"token-alice-2")
				require.ErrorIs(t, err, ErrNotFound)

				// bob's session should remain
				username, _, err := store.GetSession(ctx, prefix+"token-bob-1")
				require.NoError(t, err)
				assert.Equal(t, bobUser, username)
			})

			t.Run("delete sessions by username - no sessions", func(t *testing.T) {
				// should not error when user has no sessions
				err := store.DeleteSessionsByUsername(ctx, prefix+"nonexistent-user")
				require.NoError(t, err)
			})
		})
	}
}

// secrets tests

func newTestStoreWithEncryptor(t *testing.T, engine string) *Store {
	t.Helper()
	enc, err := NewCrypto([]byte("test-secret-key-1234"))
	require.NoError(t, err)
	return newTestStore(t, engine, WithEncryptor(enc))
}

func TestStore_SecretsEnabled(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			t.Run("false when no encryptor", func(t *testing.T) {
				store := newTestStore(t, engine)
				assert.False(t, store.SecretsEnabled())
			})

			t.Run("true when encryptor set", func(t *testing.T) {
				store := newTestStoreWithEncryptor(t, engine)
				assert.True(t, store.SecretsEnabled())
			})
		})
	}
}

func TestStore_Secrets_CRUD(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStoreWithEncryptor(t, engine)
			ctx := t.Context()
			prefix := "sec/crud/" + engine + "/"

			t.Run("set and get secret", func(t *testing.T) {
				_, err := store.Set(ctx, prefix+"secrets/db/password", []byte("super-secret"), "text")
				require.NoError(t, err)

				value, err := store.Get(ctx, prefix+"secrets/db/password")
				require.NoError(t, err)
				assert.Equal(t, []byte("super-secret"), value)
			})

			t.Run("set and get secret with format", func(t *testing.T) {
				_, err := store.Set(ctx, prefix+"app/secrets/config", []byte(`{"key":"secret"}`), "json")
				require.NoError(t, err)

				value, format, err := store.GetWithFormat(ctx, prefix+"app/secrets/config")
				require.NoError(t, err)
				assert.JSONEq(t, `{"key":"secret"}`, string(value))
				assert.Equal(t, "json", format)
			})

			t.Run("update secret", func(t *testing.T) {
				_, err := store.Set(ctx, prefix+"secrets/update-test", []byte("original"), "text")
				require.NoError(t, err)

				_, err = store.Set(ctx, prefix+"secrets/update-test", []byte("updated"), "text")
				require.NoError(t, err)

				value, err := store.Get(ctx, prefix+"secrets/update-test")
				require.NoError(t, err)
				assert.Equal(t, []byte("updated"), value)
			})

			t.Run("delete secret", func(t *testing.T) {
				_, err := store.Set(ctx, prefix+"secrets/delete-test", []byte("to-delete"), "text")
				require.NoError(t, err)

				err = store.Delete(ctx, prefix+"secrets/delete-test")
				require.NoError(t, err)

				_, err = store.Get(ctx, prefix+"secrets/delete-test")
				assert.ErrorIs(t, err, ErrNotFound)
			})

			t.Run("get info for secret", func(t *testing.T) {
				_, err := store.Set(ctx, prefix+"secrets/info-test", []byte("test-value"), "yaml")
				require.NoError(t, err)

				info, err := store.GetInfo(ctx, prefix+"secrets/info-test")
				require.NoError(t, err)
				assert.Equal(t, prefix+"secrets/info-test", info.Key)
				assert.Equal(t, "yaml", info.Format)
				assert.True(t, info.Secret, "secret flag should be true")
				assert.Positive(t, info.Size) // encrypted size is larger than plaintext
			})

			t.Run("get info for non-secret", func(t *testing.T) {
				_, err := store.Set(ctx, prefix+"config/database", []byte("test"), "text")
				require.NoError(t, err)

				info, err := store.GetInfo(ctx, prefix+"config/database")
				require.NoError(t, err)
				assert.Equal(t, prefix+"config/database", info.Key)
				assert.False(t, info.Secret, "secret flag should be false")
			})

			t.Run("secret value is encrypted in database", func(t *testing.T) {
				secretValue := []byte("plaintext-secret")
				key := prefix + "secrets/encrypted-check"
				_, err := store.Set(ctx, key, secretValue, "text")
				require.NoError(t, err)

				// read raw value from database
				var rawValue []byte
				err = store.db.Get(&rawValue, store.adoptQuery("SELECT value FROM kv WHERE key = ?"), key)
				require.NoError(t, err)

				// raw value should not equal plaintext
				assert.NotEqual(t, secretValue, rawValue, "stored value should be encrypted")

				// but Get should return decrypted value
				decrypted, err := store.Get(ctx, key)
				require.NoError(t, err)
				assert.Equal(t, secretValue, decrypted)
			})

			t.Run("regular key is not encrypted", func(t *testing.T) {
				regularValue := []byte("regular-value")
				key := prefix + "config/regular"
				_, err := store.Set(ctx, key, regularValue, "text")
				require.NoError(t, err)

				// read raw value from database
				var rawValue []byte
				err = store.db.Get(&rawValue, store.adoptQuery("SELECT value FROM kv WHERE key = ?"), key)
				require.NoError(t, err)

				// raw value should equal plaintext
				assert.Equal(t, regularValue, rawValue, "regular value should not be encrypted")
			})
		})
	}
}

func TestStore_Secrets_ZKPrecedence(t *testing.T) {
	// ZK-encrypted values in secrets paths should NOT be double-encrypted.
	// ZK encryption takes precedence over server-side encryption.

	// create valid ZK payloads using ZKCrypto
	zk, err := NewZKCrypto([]byte("test-passphrase-min-16"))
	require.NoError(t, err)

	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStoreWithEncryptor(t, engine)
			ctx := t.Context()
			prefix := "zk-prec/" + engine + "/"

			t.Run("ZK value in secrets path is not double-encrypted", func(t *testing.T) {
				zkValue, err := zk.Encrypt([]byte("api-key-value"))
				require.NoError(t, err)
				key := prefix + "secrets/zk-api-key"

				_, err = store.Set(ctx, key, zkValue, "text")
				require.NoError(t, err)

				// get should return the ZK value as-is (not decrypted by server)
				value, err := store.Get(ctx, key)
				require.NoError(t, err)
				assert.Equal(t, zkValue, value, "ZK value should be returned as-is")
			})

			t.Run("GetInfo shows both Secret and ZKEncrypted for ZK in secrets path", func(t *testing.T) {
				zkValue, err := zk.Encrypt([]byte("another-zk-value"))
				require.NoError(t, err)
				key := prefix + "app/secrets/zk-creds"

				_, err = store.Set(ctx, key, zkValue, "text")
				require.NoError(t, err)

				info, err := store.GetInfo(ctx, key)
				require.NoError(t, err)
				assert.True(t, info.Secret, "Secret flag should be true for secrets path")
				assert.True(t, info.ZKEncrypted, "ZKEncrypted should be true for $ZK$ value")
			})

			t.Run("raw storage has $ZK$ prefix for ZK values in secrets path", func(t *testing.T) {
				zkValue, err := zk.Encrypt([]byte("raw-storage-test"))
				require.NoError(t, err)
				key := prefix + "secrets/raw-check"

				_, err = store.Set(ctx, key, zkValue, "text")
				require.NoError(t, err)

				// check raw value in database - should have $ZK$ prefix, not encrypted
				var rawValue []byte
				err = store.db.Get(&rawValue, store.adoptQuery("SELECT value FROM kv WHERE key = ?"), key)
				require.NoError(t, err)
				assert.True(t, IsZKEncrypted(rawValue), "raw stored value should have $ZK$ prefix")
				assert.Equal(t, zkValue, rawValue, "raw value should match original ZK value")
			})

			t.Run("GetWithFormat returns ZK value as-is in secrets path", func(t *testing.T) {
				zkValue, err := zk.Encrypt([]byte("format-test-value"))
				require.NoError(t, err)
				key := prefix + "secrets/format-test"

				_, err = store.Set(ctx, key, zkValue, "json")
				require.NoError(t, err)

				value, format, err := store.GetWithFormat(ctx, key)
				require.NoError(t, err)
				assert.Equal(t, zkValue, value, "ZK value should be returned as-is via GetWithFormat")
				assert.Equal(t, "json", format)
			})

			t.Run("SetWithVersion works with ZK values in secrets path", func(t *testing.T) {
				zkValue, err := zk.Encrypt([]byte("version-test-value"))
				require.NoError(t, err)
				key := prefix + "secrets/version-test"

				// first set
				_, err = store.Set(ctx, key, zkValue, "text")
				require.NoError(t, err)

				// get current version
				info, err := store.GetInfo(ctx, key)
				require.NoError(t, err)

				// update with version
				newZKValue, err := zk.Encrypt([]byte("updated-version-value"))
				require.NoError(t, err)
				err = store.SetWithVersion(ctx, key, newZKValue, "text", info.UpdatedAt)
				require.NoError(t, err)

				// verify updated value
				value, err := store.Get(ctx, key)
				require.NoError(t, err)
				assert.Equal(t, newZKValue, value)
			})
		})
	}
}

func TestStore_ZKPayload_Validation(t *testing.T) {
	// invalid ZK payloads should be rejected only in secrets paths
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStoreWithEncryptor(t, engine)
			ctx := t.Context()
			prefix := "zk-valid/" + engine + "/"

			invalidPayloads := []struct {
				name  string
				value []byte
			}{
				{"plaintext with ZK prefix", []byte("$ZK$plaintext")},
				{"short base64 with ZK prefix", []byte("$ZK$aGVsbG8=")},
				{"invalid base64 with ZK prefix", []byte("$ZK$not-valid!!!")},
			}

			t.Run("rejected in secrets paths", func(t *testing.T) {
				for _, tc := range invalidPayloads {
					t.Run(tc.name, func(t *testing.T) {
						_, err := store.Set(ctx, prefix+"secrets/key", tc.value, "text")
						assert.ErrorIs(t, err, ErrInvalidZKPayload)
					})
				}
			})

			t.Run("allowed in non-secrets paths", func(t *testing.T) {
				for _, tc := range invalidPayloads {
					t.Run(tc.name, func(t *testing.T) {
						key := prefix + "regular/" + tc.name
						_, err := store.Set(ctx, key, tc.value, "text")
						require.NoError(t, err, "invalid ZK should be allowed in non-secrets paths")

						// verify it's stored as-is
						value, err := store.Get(ctx, key)
						require.NoError(t, err)
						assert.Equal(t, tc.value, value)
					})
				}
			})

			t.Run("SetWithVersion rejects invalid ZK payload in secrets path", func(t *testing.T) {
				err := store.SetWithVersion(ctx, prefix+"secrets/invalid-zk",
					[]byte("$ZK$invalid!!!"), "text", time.Now())
				assert.ErrorIs(t, err, ErrInvalidZKPayload)
			})
		})
	}
}

func TestStore_Secrets_WithoutEncryptor(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStore(t, engine) // no encryptor
			ctx := t.Context()
			prefix := "sec/noenc/" + engine + "/"

			t.Run("set secret returns error", func(t *testing.T) {
				_, err := store.Set(ctx, prefix+"secrets/test", []byte("value"), "text")
				assert.ErrorIs(t, err, ErrSecretsNotConfigured)
			})

			t.Run("get secret returns error", func(t *testing.T) {
				_, err := store.Get(ctx, prefix+"secrets/test")
				assert.ErrorIs(t, err, ErrSecretsNotConfigured)
			})

			t.Run("get secret with format returns error", func(t *testing.T) {
				_, _, err := store.GetWithFormat(ctx, prefix+"secrets/test")
				assert.ErrorIs(t, err, ErrSecretsNotConfigured)
			})

			t.Run("regular keys work without encryptor", func(t *testing.T) {
				_, err := store.Set(ctx, prefix+"config/regular", []byte("value"), "text")
				require.NoError(t, err)

				value, err := store.Get(ctx, prefix+"config/regular")
				require.NoError(t, err)
				assert.Equal(t, []byte("value"), value)
			})

			t.Run("get info for secret returns error", func(t *testing.T) {
				_, err := store.GetInfo(ctx, prefix+"secrets/test")
				assert.ErrorIs(t, err, ErrSecretsNotConfigured)
			})

			t.Run("delete secret works without encryptor", func(t *testing.T) {
				// delete doesn't require decryption, so it should work even without encryptor
				// first verify the key doesn't exist
				err := store.Delete(ctx, prefix+"secrets/nonexistent")
				assert.ErrorIs(t, err, ErrNotFound)
			})
		})
	}
}

func TestStore_Secrets_ListFilter(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStoreWithEncryptor(t, engine)
			ctx := t.Context()
			prefix := "sec/filter/" + engine + "/"

			// create mix of secret and regular keys
			_, err := store.Set(ctx, prefix+"config/db", []byte("v1"), "text")
			require.NoError(t, err)
			_, err = store.Set(ctx, prefix+"config/app", []byte("v2"), "text")
			require.NoError(t, err)
			_, err = store.Set(ctx, prefix+"secrets/db/password", []byte("s1"), "text")
			require.NoError(t, err)
			_, err = store.Set(ctx, prefix+"app/secrets/key", []byte("s2"), "text")
			require.NoError(t, err)

			t.Run("list all keys", func(t *testing.T) {
				keys, err := store.List(ctx, enum.SecretsFilterAll)
				require.NoError(t, err)

				// count our keys only (postgres may have keys from other tests)
				var ourKeys, secretCount int
				for _, k := range keys {
					if len(k.Key) > len(prefix) && k.Key[:len(prefix)] == prefix {
						ourKeys++
						if k.Secret {
							secretCount++
						}
					}
				}
				assert.Equal(t, 4, ourKeys)
				assert.Equal(t, 2, secretCount)
			})

			t.Run("list only secrets", func(t *testing.T) {
				keys, err := store.List(ctx, enum.SecretsFilterSecretsOnly)
				require.NoError(t, err)

				// count our secret keys
				var ourSecrets int
				for _, k := range keys {
					if len(k.Key) > len(prefix) && k.Key[:len(prefix)] == prefix {
						ourSecrets++
						assert.True(t, k.Secret, "all keys should be secrets")
						assert.True(t, IsSecret(k.Key), "key path should match secret pattern")
					}
				}
				assert.Equal(t, 2, ourSecrets)
			})

			t.Run("list only non-secrets", func(t *testing.T) {
				keys, err := store.List(ctx, enum.SecretsFilterKeysOnly)
				require.NoError(t, err)

				// count our non-secret keys
				var ourKeys int
				for _, k := range keys {
					if len(k.Key) > len(prefix) && k.Key[:len(prefix)] == prefix {
						ourKeys++
						assert.False(t, k.Secret, "all keys should be non-secrets")
						assert.False(t, IsSecret(k.Key), "key path should not match secret pattern")
					}
				}
				assert.Equal(t, 2, ourKeys)
			})
		})
	}
}

func TestStore_Secrets_SetWithVersion(t *testing.T) {
	for _, engine := range testEngines {
		t.Run(engine, func(t *testing.T) {
			store := newTestStoreWithEncryptor(t, engine)
			ctx := t.Context()
			prefix := "sec/ver/" + engine + "/"

			t.Run("update secret with correct version", func(t *testing.T) {
				_, err := store.Set(ctx, prefix+"secrets/versioned", []byte("v1"), "text")
				require.NoError(t, err)

				info, err := store.GetInfo(ctx, prefix+"secrets/versioned")
				require.NoError(t, err)

				err = store.SetWithVersion(ctx, prefix+"secrets/versioned", []byte("v2"), "text", info.UpdatedAt)
				require.NoError(t, err)

				value, err := store.Get(ctx, prefix+"secrets/versioned")
				require.NoError(t, err)
				assert.Equal(t, []byte("v2"), value)
			})

			t.Run("update secret without encryptor returns error", func(t *testing.T) {
				storeNoEnc := newTestStore(t, engine)

				err := storeNoEnc.SetWithVersion(ctx, prefix+"secrets/test", []byte("v"), "text", time.Now())
				assert.ErrorIs(t, err, ErrSecretsNotConfigured)
			})

			t.Run("conflict returns decrypted secret value", func(t *testing.T) {
				secretValue := "super-secret-password"
				key := prefix + "secrets/conflict-key"
				_, err := store.Set(ctx, key, []byte(secretValue), "text")
				require.NoError(t, err)

				// get initial version
				info1, err := store.GetInfo(ctx, key)
				require.NoError(t, err)

				// simulate concurrent update
				time.Sleep(1100 * time.Millisecond) // ensure timestamp differs
				concurrentValue := "concurrent-secret-value"
				_, err = store.Set(ctx, key, []byte(concurrentValue), "yaml")
				require.NoError(t, err)

				// try to update with old version - should get conflict
				err = store.SetWithVersion(ctx, key, []byte("my-attempt"), "json", info1.UpdatedAt)
				require.ErrorIs(t, err, ErrConflict)

				// verify ConflictError returns decrypted value, not encrypted ciphertext
				var conflictErr *ConflictError
				require.ErrorAs(t, err, &conflictErr)
				assert.Equal(t, []byte(concurrentValue), conflictErr.Info.CurrentValue,
					"conflict error should contain decrypted secret value, not encrypted ciphertext")
				assert.Equal(t, "yaml", conflictErr.Info.CurrentFormat)
			})
		})
	}
}
