package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-pkgz/testutils/containers"
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

func TestSQLite_List(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	t.Run("empty store returns empty slice", func(t *testing.T) {
		keys, err := store.List()
		require.NoError(t, err)
		assert.Empty(t, keys)
	})

	t.Run("returns keys with correct metadata", func(t *testing.T) {
		err := store.Set("key1", []byte("short"))
		require.NoError(t, err)
		err = store.Set("key2", []byte("longer value here"))
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
		assert.False(t, key1Info.CreatedAt.IsZero())
		assert.False(t, key1Info.UpdatedAt.IsZero())
	})

	t.Run("ordered by updated_at descending", func(t *testing.T) {
		store2 := newTestStore(t)
		defer store2.Close()

		// create keys with delay to ensure different timestamps
		err := store2.Set("first", []byte("1"))
		require.NoError(t, err)
		time.Sleep(1100 * time.Millisecond) // RFC3339 has second precision
		err = store2.Set("second", []byte("2"))
		require.NoError(t, err)

		keys, err := store2.List()
		require.NoError(t, err)
		require.Len(t, keys, 2)

		// most recently updated should be first
		assert.Equal(t, "second", keys[0].Key)
		assert.Equal(t, "first", keys[1].Key)
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
		err := store.Set("pgkey1", []byte("pgvalue1"))
		require.NoError(t, err)

		value, err := store.Get("pgkey1")
		require.NoError(t, err)
		assert.Equal(t, []byte("pgvalue1"), value)
	})

	t.Run("update existing key", func(t *testing.T) {
		err := store.Set("pgkey2", []byte("original"))
		require.NoError(t, err)

		err = store.Set("pgkey2", []byte("updated"))
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
		err := store.Set("pgbinary", binary)
		require.NoError(t, err)

		value, err := store.Get("pgbinary")
		require.NoError(t, err)
		assert.Equal(t, binary, value)
	})

	t.Run("delete existing key", func(t *testing.T) {
		err := store.Set("pgtodelete", []byte("value"))
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
		err := store.Set("pglist1", []byte("short"))
		require.NoError(t, err)
		err = store.Set("pglist2", []byte("longer value"))
		require.NoError(t, err)

		keys, err := store.List()
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(keys), 2)

		// find our keys
		var found1, found2 bool
		for _, k := range keys {
			if k.Key == "pglist1" {
				assert.Equal(t, 5, k.Size)
				found1 = true
			}
			if k.Key == "pglist2" {
				assert.Equal(t, 12, k.Size)
				found2 = true
			}
		}
		assert.True(t, found1, "pglist1 not found")
		assert.True(t, found2, "pglist2 not found")
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
	// sQLite store - no changes
	sqliteStore := &Store{dbType: DBTypeSQLite}
	assert.Equal(t, "SELECT * FROM kv WHERE key = ?", sqliteStore.adoptQuery("SELECT * FROM kv WHERE key = ?"))

	// postgreSQL store - converts placeholders
	pgStore := &Store{dbType: DBTypePostgres}
	assert.Equal(t, "SELECT * FROM kv WHERE key = $1", pgStore.adoptQuery("SELECT * FROM kv WHERE key = ?"))
	assert.Equal(t, "INSERT INTO kv VALUES ($1, $2, $3)", pgStore.adoptQuery("INSERT INTO kv VALUES (?, ?, ?)"))
}

// Service Discovery Tests

func TestStore_RegisterService(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	t.Run("register new service", func(t *testing.T) {
		svc := ServiceInstance{
			ID:        "svc-1",
			Name:      "api",
			Address:   "10.0.0.1",
			Port:      8080,
			Tags:      []string{"primary", "zone-a"},
			CheckType: HealthCheckTTL,
			TTL:       30,
		}
		err := store.RegisterService(svc)
		require.NoError(t, err)

		// verify service exists
		services, err := store.GetServices("api", false)
		require.NoError(t, err)
		require.Len(t, services, 1)
		assert.Equal(t, "svc-1", services[0].ID)
		assert.Equal(t, "10.0.0.1", services[0].Address)
		assert.Equal(t, 8080, services[0].Port)
		assert.Equal(t, []string{"primary", "zone-a"}, services[0].Tags)
		assert.True(t, services[0].Healthy)
	})

	t.Run("update existing service", func(t *testing.T) {
		svc := ServiceInstance{
			ID:      "svc-1",
			Name:    "api",
			Address: "10.0.0.2", // changed
			Port:    9090,       // changed
		}
		err := store.RegisterService(svc)
		require.NoError(t, err)

		services, err := store.GetServices("api", false)
		require.NoError(t, err)
		require.Len(t, services, 1)
		assert.Equal(t, "10.0.0.2", services[0].Address)
		assert.Equal(t, 9090, services[0].Port)
	})
}

func TestStore_DeregisterService(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	svc := ServiceInstance{ID: "svc-del", Name: "api", Address: "10.0.0.1", Port: 8080}
	require.NoError(t, store.RegisterService(svc))

	t.Run("deregister existing service", func(t *testing.T) {
		err := store.DeregisterService("api", "svc-del")
		require.NoError(t, err)

		services, err := store.GetServices("api", false)
		require.NoError(t, err)
		assert.Empty(t, services)
	})

	t.Run("deregister nonexistent service", func(t *testing.T) {
		err := store.DeregisterService("api", "nonexistent")
		require.ErrorIs(t, err, ErrServiceNotFound)
	})
}

func TestStore_UpdateServiceHealth(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	svc := ServiceInstance{ID: "svc-health", Name: "api", Address: "10.0.0.1", Port: 8080, CheckType: HealthCheckTTL, TTL: 30}
	require.NoError(t, store.RegisterService(svc))

	t.Run("update health of existing service", func(t *testing.T) {
		err := store.UpdateServiceHealth("api", "svc-health")
		require.NoError(t, err)
	})

	t.Run("update health of nonexistent service", func(t *testing.T) {
		err := store.UpdateServiceHealth("api", "nonexistent")
		require.ErrorIs(t, err, ErrServiceNotFound)
	})
}

func TestStore_SetServiceHealthStatus(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	svc := ServiceInstance{ID: "svc-status", Name: "api", Address: "10.0.0.1", Port: 8080}
	require.NoError(t, store.RegisterService(svc))

	t.Run("set service unhealthy", func(t *testing.T) {
		err := store.SetServiceHealthStatus("api", "svc-status", false)
		require.NoError(t, err)

		services, err := store.GetServices("api", false)
		require.NoError(t, err)
		require.Len(t, services, 1)
		assert.False(t, services[0].Healthy)
	})

	t.Run("set service healthy", func(t *testing.T) {
		err := store.SetServiceHealthStatus("api", "svc-status", true)
		require.NoError(t, err)

		services, err := store.GetServices("api", false)
		require.NoError(t, err)
		require.Len(t, services, 1)
		assert.True(t, services[0].Healthy)
	})
}

func TestStore_GetServices(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	// register multiple services
	require.NoError(t, store.RegisterService(ServiceInstance{ID: "svc-1", Name: "api", Address: "10.0.0.1", Port: 8080}))
	require.NoError(t, store.RegisterService(ServiceInstance{ID: "svc-2", Name: "api", Address: "10.0.0.2", Port: 8080}))
	require.NoError(t, store.RegisterService(ServiceInstance{ID: "svc-3", Name: "db", Address: "10.0.0.3", Port: 5432}))

	// mark one as unhealthy
	require.NoError(t, store.SetServiceHealthStatus("api", "svc-2", false))

	t.Run("get all services by name", func(t *testing.T) {
		services, err := store.GetServices("api", false)
		require.NoError(t, err)
		assert.Len(t, services, 2)
	})

	t.Run("get only healthy services", func(t *testing.T) {
		services, err := store.GetServices("api", true)
		require.NoError(t, err)
		assert.Len(t, services, 1)
		assert.Equal(t, "svc-1", services[0].ID)
	})

	t.Run("get services for different name", func(t *testing.T) {
		services, err := store.GetServices("db", false)
		require.NoError(t, err)
		assert.Len(t, services, 1)
		assert.Equal(t, "svc-3", services[0].ID)
	})
}

func TestStore_ListServicesSummary(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	require.NoError(t, store.RegisterService(ServiceInstance{ID: "api-1", Name: "api", Address: "10.0.0.1", Port: 8080}))
	require.NoError(t, store.RegisterService(ServiceInstance{ID: "api-2", Name: "api", Address: "10.0.0.2", Port: 8080}))
	require.NoError(t, store.RegisterService(ServiceInstance{ID: "db-1", Name: "db", Address: "10.0.0.3", Port: 5432}))
	require.NoError(t, store.SetServiceHealthStatus("api", "api-2", false))

	summaries, err := store.ListServicesSummary()
	require.NoError(t, err)
	require.Len(t, summaries, 2)

	// find api summary
	var apiSummary, dbSummary *ServiceSummary
	for i := range summaries {
		if summaries[i].Name == "api" {
			apiSummary = &summaries[i]
		}
		if summaries[i].Name == "db" {
			dbSummary = &summaries[i]
		}
	}

	require.NotNil(t, apiSummary)
	assert.Equal(t, 2, apiSummary.Instances)
	assert.Equal(t, 1, apiSummary.Healthy)

	require.NotNil(t, dbSummary)
	assert.Equal(t, 1, dbSummary.Instances)
	assert.Equal(t, 1, dbSummary.Healthy)
}

func TestStore_MarkExpiredTTLServices(t *testing.T) {
	store := newTestStore(t)
	defer store.Close()

	// register service with 1 second TTL
	svc := ServiceInstance{ID: "svc-ttl", Name: "api", Address: "10.0.0.1", Port: 8080, CheckType: HealthCheckTTL, TTL: 1}
	require.NoError(t, store.RegisterService(svc))

	// should be healthy initially
	services, err := store.GetServices("api", true)
	require.NoError(t, err)
	assert.Len(t, services, 1)

	// wait for TTL to expire (2s to ensure clear second boundary crossing)
	time.Sleep(2 * time.Second)

	// mark expired services
	count, err := store.MarkExpiredTTLServices()
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// should now be unhealthy
	services, err = store.GetServices("api", true)
	require.NoError(t, err)
	assert.Empty(t, services)

	services, err = store.GetServices("api", false)
	require.NoError(t, err)
	assert.Len(t, services, 1)
	assert.False(t, services[0].Healthy)
}
