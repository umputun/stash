// Package store provides key-value storage implementations.
package store

import "errors"

// ErrNotFound is returned when a key is not found in the store.
var ErrNotFound = errors.New("key not found")
