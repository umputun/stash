// Package store provides key-value storage implementations.
package store

import (
	"errors"
	"strings"
	"time"

	"github.com/umputun/stash/app/enum"
)

// ErrNotFound is returned when a key is not found in the store.
var ErrNotFound = errors.New("key not found")

// ErrConflict is returned when optimistic locking fails due to concurrent modification.
var ErrConflict = errors.New("version conflict")

// ConflictInfo holds details about a detected version conflict.
type ConflictInfo struct {
	CurrentValue     []byte
	CurrentFormat    string
	CurrentVersion   time.Time
	AttemptedVersion time.Time
}

// ConflictError wraps ErrConflict with conflict details for UI display.
type ConflictError struct {
	Info ConflictInfo
}

// Error returns a string representation of the conflict.
func (e *ConflictError) Error() string {
	return "version conflict: key was modified since " + e.Info.AttemptedVersion.Format(time.RFC3339)
}

// Unwrap returns the underlying ErrConflict sentinel.
func (e *ConflictError) Unwrap() error {
	return ErrConflict
}

// Interface defines the contract for key-value storage operations.
// Both Store (concrete DB) and Cached (wrapper) implement this interface.
type Interface interface {
	Get(key string) ([]byte, error)
	GetWithFormat(key string) ([]byte, string, error)
	GetInfo(key string) (KeyInfo, error)
	Set(key string, value []byte, format string) error
	SetWithVersion(key string, value []byte, format string, expectedVersion time.Time) error
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

// DBType is an alias for enum.DbType for compatibility.
type DBType = enum.DbType

// Database type constants for convenience.
var (
	DBTypeSQLite   = enum.DbTypeSQLite
	DBTypePostgres = enum.DbTypePostgres
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

// NormalizeKey normalizes a key by trimming spaces, leading/trailing slashes,
// and replacing spaces with underscores.
func NormalizeKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.Trim(key, "/")
	key = strings.ReplaceAll(key, " ", "_")
	return key
}
