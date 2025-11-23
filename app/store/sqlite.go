package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/go-pkgz/lgr"
	_ "github.com/jackc/pgx/v5/stdlib" // postgresql driver
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // sqlite driver
)

// DBType represents the database type.
type DBType int

// Database type constants.
const (
	DBTypeSQLite DBType = iota
	DBTypePostgres
)

// RWLocker is an interface for read-write locking.
type RWLocker interface {
	RLock()
	RUnlock()
	Lock()
	Unlock()
}

// noopLocker implements RWLocker with no-op operations (for PostgreSQL).
type noopLocker struct{}

func (noopLocker) RLock()   {}
func (noopLocker) RUnlock() {}
func (noopLocker) Lock()    {}
func (noopLocker) Unlock()  {}

// Store implements key-value storage using SQLite or PostgreSQL.
type Store struct {
	db     *sqlx.DB
	dbType DBType
	mu     RWLocker
}

// New creates a new Store with the given database URL.
// Automatically detects database type from URL:
// - postgres:// or postgresql:// -> PostgreSQL
// - everything else -> SQLite
func New(dbURL string) (*Store, error) {
	dbType := detectDBType(dbURL)

	var db *sqlx.DB
	var err error
	var locker RWLocker

	switch dbType {
	case DBTypePostgres:
		db, err = connectPostgres(dbURL)
		locker = noopLocker{}
	default:
		db, err = connectSQLite(dbURL)
		locker = &sync.RWMutex{}
	}

	if err != nil {
		return nil, err
	}

	s := &Store{db: db, dbType: dbType, mu: locker}

	if err := s.createSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	log.Printf("[DEBUG] initialized %s store", s.dbTypeName())
	return s, nil
}

// NewSQLite creates a new SQLite store (backward compatibility).
func NewSQLite(dbPath string) (*Store, error) {
	return New(dbPath)
}

// detectDBType determines database type from URL.
func detectDBType(url string) DBType {
	lower := strings.ToLower(url)
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		return DBTypePostgres
	}
	return DBTypeSQLite
}

// connectSQLite establishes SQLite connection with pragmas.
func connectSQLite(dbPath string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sqlite: %w", err)
	}

	// set pragmas for performance and reliability
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=1000",
		"PRAGMA foreign_keys=ON",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("failed to set pragma %q: %w", pragma, err)
		}
	}

	// limit connections for SQLite (single writer)
	db.SetMaxOpenConns(1)

	return db, nil
}

// connectPostgres establishes PostgreSQL connection.
func connectPostgres(dbURL string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("pgx", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	// set reasonable connection pool defaults
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}

// createSchema creates the kv and services tables if they don't exist.
func (s *Store) createSchema() error {
	var kvSchema, svcSchema string
	switch s.dbType {
	case DBTypePostgres:
		kvSchema = `
			CREATE TABLE IF NOT EXISTS kv (
				key TEXT PRIMARY KEY,
				value BYTEA NOT NULL,
				created_at TIMESTAMP DEFAULT NOW(),
				updated_at TIMESTAMP DEFAULT NOW()
			)`
		svcSchema = `
			CREATE TABLE IF NOT EXISTS services (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				address TEXT NOT NULL,
				port INTEGER NOT NULL,
				tags JSONB DEFAULT '[]',
				check_type TEXT DEFAULT 'ttl',
				check_url TEXT DEFAULT '',
				check_interval INTEGER DEFAULT 0,
				ttl INTEGER DEFAULT 30,
				healthy BOOLEAN DEFAULT true,
				last_seen TIMESTAMP DEFAULT NOW(),
				registered_at TIMESTAMP DEFAULT NOW()
			);
			CREATE INDEX IF NOT EXISTS idx_services_name ON services(name);
			CREATE INDEX IF NOT EXISTS idx_services_healthy ON services(healthy)`
	default:
		kvSchema = `
			CREATE TABLE IF NOT EXISTS kv (
				key TEXT PRIMARY KEY,
				value BLOB NOT NULL,
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)`
		svcSchema = `
			CREATE TABLE IF NOT EXISTS services (
				id TEXT PRIMARY KEY,
				name TEXT NOT NULL,
				address TEXT NOT NULL,
				port INTEGER NOT NULL,
				tags TEXT DEFAULT '[]',
				check_type TEXT DEFAULT 'ttl',
				check_url TEXT DEFAULT '',
				check_interval INTEGER DEFAULT 0,
				ttl INTEGER DEFAULT 30,
				healthy INTEGER DEFAULT 1,
				last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
				registered_at DATETIME DEFAULT CURRENT_TIMESTAMP
			);
			CREATE INDEX IF NOT EXISTS idx_services_name ON services(name);
			CREATE INDEX IF NOT EXISTS idx_services_healthy ON services(healthy)`
	}
	if _, err := s.db.Exec(kvSchema); err != nil {
		return fmt.Errorf("failed to create kv schema: %w", err)
	}
	if _, err := s.db.Exec(svcSchema); err != nil {
		return fmt.Errorf("failed to create services schema: %w", err)
	}
	return nil
}

// dbTypeName returns human-readable database type name.
func (s *Store) dbTypeName() string {
	switch s.dbType {
	case DBTypePostgres:
		return "postgres"
	default:
		return "sqlite"
	}
}

// Get retrieves the value for the given key.
// Returns ErrNotFound if the key does not exist.
func (s *Store) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var value []byte
	query := s.adoptQuery("SELECT value FROM kv WHERE key = ?")
	err := s.db.Get(&value, query, key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get key %q: %w", key, err)
	}
	return value, nil
}

// Set stores the value for the given key.
// Creates a new key or updates an existing one.
func (s *Store) Set(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var query string
	switch s.dbType {
	case DBTypePostgres:
		query = `
			INSERT INTO kv (key, value, created_at, updated_at) VALUES ($1, $2, $3, $4)
			ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`
	default:
		query = `
			INSERT INTO kv (key, value, created_at, updated_at) VALUES (?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
	}
	if _, err := s.db.Exec(query, key, value, now, now); err != nil {
		return fmt.Errorf("failed to set key %q: %w", key, err)
	}
	return nil
}

// Delete removes the key from the store.
// Returns ErrNotFound if the key does not exist.
func (s *Store) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := s.adoptQuery("DELETE FROM kv WHERE key = ?")
	result, err := s.db.Exec(query, key)
	if err != nil {
		return fmt.Errorf("failed to delete key %q: %w", key, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

// List returns metadata for all keys, ordered by updated_at descending.
func (s *Store) List() ([]KeyInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []KeyInfo
	var query string
	switch s.dbType {
	case DBTypePostgres:
		query = `SELECT key, octet_length(value) as size, created_at, updated_at FROM kv ORDER BY updated_at DESC`
	default:
		query = `SELECT key, length(value) as size, created_at, updated_at FROM kv ORDER BY updated_at DESC`
	}
	if err := s.db.Select(&keys, query); err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	return keys, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}
	return nil
}

// adoptQuery converts SQLite placeholders (?) to PostgreSQL ($1, $2, ...).
func (s *Store) adoptQuery(query string) string {
	if s.dbType != DBTypePostgres {
		return query
	}

	result := make([]byte, 0, len(query)+10)
	paramNum := 1
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			result = append(result, '$')
			result = append(result, fmt.Sprintf("%d", paramNum)...)
			paramNum++
		} else {
			result = append(result, query[i])
		}
	}
	return string(result)
}

// Service Discovery Methods

// RegisterService adds or updates a service instance.
func (s *Store) RegisterService(svc ServiceInstance) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	tagsJSON, err := json.Marshal(svc.Tags)
	if err != nil {
		return fmt.Errorf("failed to marshal tags: %w", err)
	}

	var query string
	var nowVal interface{}
	switch s.dbType {
	case DBTypePostgres:
		nowVal = now
		query = `
			INSERT INTO services (id, name, address, port, tags, check_type, check_url, check_interval, ttl, healthy, last_seen, registered_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT(id) DO UPDATE SET
				name = EXCLUDED.name, address = EXCLUDED.address, port = EXCLUDED.port,
				tags = EXCLUDED.tags, check_type = EXCLUDED.check_type, check_url = EXCLUDED.check_url,
				check_interval = EXCLUDED.check_interval, ttl = EXCLUDED.ttl, last_seen = EXCLUDED.last_seen`
	default:
		// sqlite needs timestamps in YYYY-MM-DD HH:MM:SS format for datetime() to work
		nowVal = now.Format("2006-01-02 15:04:05")
		query = `
			INSERT INTO services (id, name, address, port, tags, check_type, check_url, check_interval, ttl, healthy, last_seen, registered_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				name = excluded.name, address = excluded.address, port = excluded.port,
				tags = excluded.tags, check_type = excluded.check_type, check_url = excluded.check_url,
				check_interval = excluded.check_interval, ttl = excluded.ttl, last_seen = excluded.last_seen`
	}

	if _, err := s.db.Exec(query, svc.ID, svc.Name, svc.Address, svc.Port, string(tagsJSON),
		svc.CheckType, svc.CheckURL, svc.CheckInterval, svc.TTL, true, nowVal, nowVal); err != nil {
		return fmt.Errorf("failed to register service %q: %w", svc.ID, err)
	}
	return nil
}

// DeregisterService removes a service instance.
func (s *Store) DeregisterService(name, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := s.adoptQuery("DELETE FROM services WHERE id = ? AND name = ?")
	result, err := s.db.Exec(query, id, name)
	if err != nil {
		return fmt.Errorf("failed to deregister service %q: %w", id, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if rows == 0 {
		return ErrServiceNotFound
	}
	return nil
}

// UpdateServiceHealth updates the last_seen timestamp for a service (heartbeat).
func (s *Store) UpdateServiceHealth(name, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var nowVal interface{}
	if s.dbType == DBTypeSQLite {
		nowVal = now.Format("2006-01-02 15:04:05")
	} else {
		nowVal = now
	}

	query := s.adoptQuery("UPDATE services SET last_seen = ?, healthy = ? WHERE id = ? AND name = ?")
	result, err := s.db.Exec(query, nowVal, true, id, name)
	if err != nil {
		return fmt.Errorf("failed to update service health %q: %w", id, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if rows == 0 {
		return ErrServiceNotFound
	}
	return nil
}

// SetServiceHealthStatus sets the health status of a service instance.
func (s *Store) SetServiceHealthStatus(name, id string, healthy bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := s.adoptQuery("UPDATE services SET healthy = ? WHERE id = ? AND name = ?")
	result, err := s.db.Exec(query, healthy, id, name)
	if err != nil {
		return fmt.Errorf("failed to set service health status %q: %w", id, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if rows == 0 {
		return ErrServiceNotFound
	}
	return nil
}

// GetServices retrieves service instances by name with optional filtering.
func (s *Store) GetServices(name string, healthyOnly bool) ([]ServiceInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var services []ServiceInstance
	var query string
	if healthyOnly {
		query = s.adoptQuery("SELECT * FROM services WHERE name = ? AND healthy = ? ORDER BY registered_at")
		if err := s.db.Select(&services, query, name, true); err != nil {
			return nil, fmt.Errorf("failed to get services: %w", err)
		}
	} else {
		query = s.adoptQuery("SELECT * FROM services WHERE name = ? ORDER BY registered_at")
		if err := s.db.Select(&services, query, name); err != nil {
			return nil, fmt.Errorf("failed to get services: %w", err)
		}
	}

	// unmarshal tags from JSON
	for i := range services {
		if services[i].TagsJSON != "" {
			_ = json.Unmarshal([]byte(services[i].TagsJSON), &services[i].Tags)
		}
	}
	return services, nil
}

// GetServicesForHealthCheck retrieves all services of a given check type.
func (s *Store) GetServicesForHealthCheck(checkType HealthCheckType) ([]ServiceInstance, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var services []ServiceInstance
	query := s.adoptQuery("SELECT * FROM services WHERE check_type = ?")
	if err := s.db.Select(&services, query, checkType); err != nil {
		return nil, fmt.Errorf("failed to get services for health check: %w", err)
	}

	for i := range services {
		if services[i].TagsJSON != "" {
			_ = json.Unmarshal([]byte(services[i].TagsJSON), &services[i].Tags)
		}
	}
	return services, nil
}

// ListServicesSummary returns a summary of all registered services.
func (s *Store) ListServicesSummary() ([]ServiceSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var summaries []ServiceSummary
	query := `SELECT name, COUNT(*) as instances, SUM(CASE WHEN healthy THEN 1 ELSE 0 END) as healthy FROM services GROUP BY name ORDER BY name`
	if s.dbType == DBTypeSQLite {
		query = `SELECT name, COUNT(*) as instances, SUM(CASE WHEN healthy = 1 THEN 1 ELSE 0 END) as healthy FROM services GROUP BY name ORDER BY name`
	}
	if err := s.db.Select(&summaries, query); err != nil {
		return nil, fmt.Errorf("failed to list services summary: %w", err)
	}
	return summaries, nil
}

// CleanupStaleServices removes services that have been unhealthy longer than threshold.
func (s *Store) CleanupStaleServices(threshold time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().Add(-threshold)
	query := s.adoptQuery("DELETE FROM services WHERE healthy = ? AND last_seen < ?")
	result, err := s.db.Exec(query, false, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup stale services: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to check affected rows: %w", err)
	}
	return int(rows), nil
}

// MarkExpiredTTLServices marks TTL-based services as unhealthy if their TTL has expired.
func (s *Store) MarkExpiredTTLServices() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	// mark services unhealthy where: check_type = 'ttl' AND healthy = true AND last_seen + ttl < now
	var query string
	var args []interface{}
	switch s.dbType {
	case DBTypePostgres:
		query = `UPDATE services SET healthy = false WHERE check_type = 'ttl' AND healthy = true AND last_seen + (ttl || ' seconds')::interval < $1`
		args = []interface{}{now}
	default:
		// sqlite: use substr to extract YYYY-MM-DD HH:MM:SS from stored timestamp
		query = `UPDATE services SET healthy = 0 WHERE check_type = 'ttl' AND healthy = 1 AND datetime(substr(last_seen, 1, 19), '+' || ttl || ' seconds') < datetime(?)`
		args = []interface{}{now.Format("2006-01-02 15:04:05")}
	}

	result, err := s.db.Exec(query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to mark expired TTL services: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to check affected rows: %w", err)
	}
	return int(rows), nil
}
