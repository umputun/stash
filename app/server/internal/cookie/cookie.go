// Package cookie provides shared cookie-related constants.
package cookie

const (
	// NameSecure is the cookie name with __Host- prefix for HTTPS security.
	// requires HTTPS, secure flag, and path="/".
	NameSecure = "__Host-stash-auth"

	// NameFallback is the cookie name for HTTP/development environments.
	NameFallback = "stash-auth"
)

// SessionCookieNames defines cookie names for session authentication.
// Order matters: __Host- prefix is tried first (for HTTPS security), then fallback.
// __Host- prefix requires HTTPS, secure, path=/ (preferred for production).
// Fallback cookie name works on HTTP for development.
var SessionCookieNames = []string{NameSecure, NameFallback}
