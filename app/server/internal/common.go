// Package internal provides shared utilities for server subpackages.
package internal

import "strings"

// SessionCookieNames defines cookie names for session authentication.
// __Host- prefix requires HTTPS, secure, path=/ (preferred for production).
// fallback cookie name works on HTTP for development.
var SessionCookieNames = []string{"__Host-stash-auth", "stash-auth"}

// NormalizeKey normalizes a key by trimming spaces, leading/trailing slashes,
// and replacing spaces with underscores.
func NormalizeKey(key string) string {
	key = strings.TrimSpace(key)
	key = strings.Trim(key, "/")
	key = strings.ReplaceAll(key, " ", "_")
	return key
}
