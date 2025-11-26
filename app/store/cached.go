package store

import (
	"fmt"

	"github.com/go-pkgz/lcw/v2"
)

// cacheEntry holds cached value and format together.
type cacheEntry struct {
	value  []byte
	format string
}

// Cached wraps a store Interface with a loading cache and satisfies the Interface itself.
// Cache is populated on reads via loader function, invalidated on writes.
type Cached struct {
	store Interface
	cache lcw.LoadingCache[cacheEntry]
}

// NewCached creates a new cached store wrapper.
// maxKeys sets the maximum number of entries in the cache.
func NewCached(store Interface, maxKeys int) (*Cached, error) {
	cache, err := lcw.NewLruCache(lcw.NewOpts[cacheEntry]().MaxKeys(maxKeys))
	if err != nil {
		return nil, fmt.Errorf("failed to create cache: %w", err)
	}
	return &Cached{store: store, cache: cache}, nil
}

// Get retrieves the value for a key, using cache with load-through.
func (c *Cached) Get(key string) ([]byte, error) {
	entry, err := c.cache.Get(key, func() (cacheEntry, error) {
		val, format, loadErr := c.store.GetWithFormat(key)
		if loadErr != nil {
			return cacheEntry{}, fmt.Errorf("load from store: %w", loadErr)
		}
		return cacheEntry{value: val, format: format}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("cache get: %w", err)
	}
	return entry.value, nil
}

// GetWithFormat retrieves the value and format for a key, using cache with load-through.
func (c *Cached) GetWithFormat(key string) ([]byte, string, error) {
	entry, err := c.cache.Get(key, func() (cacheEntry, error) {
		val, format, loadErr := c.store.GetWithFormat(key)
		if loadErr != nil {
			return cacheEntry{}, fmt.Errorf("load from store: %w", loadErr)
		}
		return cacheEntry{value: val, format: format}, nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("cache get: %w", err)
	}
	return entry.value, entry.format, nil
}

// Set stores a value and invalidates the cache entry.
func (c *Cached) Set(key string, value []byte, format string) error {
	if err := c.store.Set(key, value, format); err != nil {
		return fmt.Errorf("store set: %w", err)
	}
	c.cache.Invalidate(func(k string) bool { return k == key })
	return nil
}

// Delete removes a key and invalidates the cache entry.
func (c *Cached) Delete(key string) error {
	// invalidate regardless of error - key might have been cached
	c.cache.Invalidate(func(k string) bool { return k == key })
	if err := c.store.Delete(key); err != nil {
		return fmt.Errorf("store delete: %w", err)
	}
	return nil
}

// List returns all keys from the underlying store (not cached).
func (c *Cached) List() ([]KeyInfo, error) {
	keys, err := c.store.List()
	if err != nil {
		return nil, fmt.Errorf("store list: %w", err)
	}
	return keys, nil
}

// Close closes the cache and underlying store.
func (c *Cached) Close() error {
	_ = c.cache.Close()
	if err := c.store.Close(); err != nil {
		return fmt.Errorf("store close: %w", err)
	}
	return nil
}

// Stats returns cache statistics.
func (c *Cached) Stats() lcw.CacheStat {
	return c.cache.Stat()
}
