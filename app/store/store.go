// Package store provides key-value storage implementations.
package store

import (
	"errors"
	"time"
)

// ErrNotFound is returned when a key is not found in the store.
var ErrNotFound = errors.New("key not found")

// Interface defines the contract for key-value storage operations.
// Both Store (concrete DB) and Cached (wrapper) implement this interface.
type Interface interface {
	Get(key string) ([]byte, error)
	GetWithFormat(key string) ([]byte, string, error)
	Set(key string, value []byte, format string) error
	Delete(key string) error
	List() ([]KeyInfo, error)
	Close() error
}

// KeyInfo holds metadata about a stored key.
type KeyInfo struct {
	Key       string    `db:"key"`
	Size      int       `db:"size"`
	Format    string    `db:"format"`
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

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
