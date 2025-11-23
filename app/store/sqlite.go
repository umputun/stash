package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // sqlite driver
)

// SQLite implements key-value storage using SQLite database.
type SQLite struct {
	db *sqlx.DB
	mu sync.RWMutex
}

// NewSQLite creates a new SQLite store with the given database path.
// It initializes the schema and sets pragmas for optimal performance.
func NewSQLite(dbPath string) (*SQLite, error) {
	db, err := sqlx.Connect("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
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

	// create schema
	schema := `
		CREATE TABLE IF NOT EXISTS kv (
			key TEXT PRIMARY KEY,
			value BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return &SQLite{db: db}, nil
}

// Get retrieves the value for the given key.
// Returns ErrNotFound if the key does not exist.
func (s *SQLite) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var value []byte
	err := s.db.Get(&value, "SELECT value FROM kv WHERE key = ?", key)
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
func (s *SQLite) Set(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	query := `
		INSERT INTO kv (key, value, created_at, updated_at) VALUES (?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
	if _, err := s.db.Exec(query, key, value, now, now); err != nil {
		return fmt.Errorf("failed to set key %q: %w", key, err)
	}
	return nil
}

// Delete removes the key from the store.
// Returns ErrNotFound if the key does not exist.
func (s *SQLite) Delete(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.Exec("DELETE FROM kv WHERE key = ?", key)
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
func (s *SQLite) List() ([]KeyInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []KeyInfo
	query := `SELECT key, length(value) as size, created_at, updated_at FROM kv ORDER BY updated_at DESC`
	if err := s.db.Select(&keys, query); err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	return keys, nil
}

// Close closes the database connection.
func (s *SQLite) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}
	return nil
}
