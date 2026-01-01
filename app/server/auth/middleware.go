package auth

import (
	"net/http"
	"strings"

	log "github.com/go-pkgz/lgr"

	"github.com/umputun/stash/app/server/internal/cookie"
	"github.com/umputun/stash/app/store"
)

// SessionMiddleware returns middleware that requires a valid session cookie.
// Used for web UI routes. Redirects to loginURL if not authenticated.
// For HTMX requests, uses HX-Redirect header to trigger full page navigation.
func (s *Service) SessionMiddleware(loginURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// check session cookie
			for _, cookieName := range cookie.SessionCookieNames {
				if c, err := r.Cookie(cookieName); err == nil && s.validateSession(r.Context(), c.Value) {
					next.ServeHTTP(w, r)
					return
				}
			}
			// no valid session - handle redirect based on request type
			if r.Header.Get("HX-Request") == "true" {
				// HTMX request: use HX-Redirect header to trigger full page navigation
				// instead of swapping login form into the target element
				w.Header().Set("HX-Redirect", loginURL)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			// regular request: use standard HTTP redirect
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
		})
	}
}

// TokenMiddleware returns middleware that requires a valid token with appropriate permissions.
// Accepts X-Auth-Token header or Authorization: Bearer <token>. Used for API routes.
// Returns 401/403 if not authorized.
// Public access (token="*") is checked first and allows unauthenticated requests.
// For list operations (empty key), only validates token existence, filtering happens in handler.
func (s *Service) TokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := store.NormalizeKey(strings.TrimPrefix(r.URL.Path, "/kv/"))
		needWrite := r.Method == http.MethodPut || r.Method == http.MethodDelete
		isList := key == "" && r.Method == http.MethodGet // list operation has no key

		// check public access first (token="*" in config)
		// for list operation, public access means pass-through (handler filters results)
		s.mu.RLock()
		publicACL := s.publicACL
		s.mu.RUnlock()
		if publicACL != nil {
			if isList || publicACL.CheckKeyPermission(key, needWrite) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// also accept session cookie for API (allows UI to call API)
		for _, cookieName := range cookie.SessionCookieNames {
			c, err := r.Cookie(cookieName)
			if err != nil {
				continue
			}
			username, valid := s.GetSessionUser(r.Context(), c.Value)
			if !valid {
				continue
			}
			// for list operation, just verify session is valid (handler filters results)
			if isList {
				next.ServeHTTP(w, r)
				return
			}
			// check user permissions for the key
			if !s.CheckUserPermission(username, key, needWrite) {
				log.Printf("[INFO] user %q denied %s access to key %q", username, r.Method, key)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}

		// check API token (X-Auth-Token or Bearer)
		token := ExtractToken(r)
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// check if token exists
		if _, ok := s.getTokenACL(token); !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// for list operation, just verify token exists (handler filters results)
		if isList {
			next.ServeHTTP(w, r)
			return
		}

		if !s.checkPermission(token, key, needWrite) {
			log.Printf("[INFO] token %q denied %s access to key %q", MaskToken(token), r.Method, key)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// MaskToken returns a masked version of token for safe logging (shows first 4 chars).
func MaskToken(token string) string {
	if len(token) <= 4 {
		return "****"
	}
	return token[:4] + "****"
}

// ExtractToken extracts API token from request headers.
// Checks X-Auth-Token header first, then Authorization: Bearer header.
// Returns the token string (may be empty if not found).
func ExtractToken(r *http.Request) string {
	// check X-Auth-Token header first (preferred for API)
	if token := r.Header.Get("X-Auth-Token"); token != "" {
		return token
	}
	// check Bearer token
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}
