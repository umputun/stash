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
				if c, err := r.Cookie(cookieName); err == nil {
					if _, ok := s.GetSessionUser(r.Context(), c.Value); ok {
						next.ServeHTTP(w, r)
						return
					}
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
// List and subscribe routes only require a valid principal; their handlers filter per key.
// The middleware must be mounted on the kv route group so the matched pattern and path
// values are available.
func (s *Service) TokenMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, principalOnly := s.requestKey(r)
		needWrite := r.Method == http.MethodPut || r.Method == http.MethodDelete

		// check public access first (token="*" in config)
		s.mu.RLock()
		publicACL := s.publicACL
		s.mu.RUnlock()
		if publicACL != nil {
			if principalOnly || publicACL.CheckKeyPermission(key, needWrite) {
				next.ServeHTTP(w, r)
				return
			}
		}

		// also accept session cookie for API (allows UI to call API)
		if allowed, handled := s.checkSessionAuth(r, key, needWrite, principalOnly, w); handled {
			if !allowed {
				return // already wrote error response
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

		if principalOnly {
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

// requestKey returns the key a kv request acts on and whether the route needs only a valid
// principal. The key comes from the matched route rather than the raw path, so
// PUT /kv/history/foo is the ordinary key "history/foo" while GET /kv/history/foo checks "foo".
// Subscribe routes are principal-only: the SSE service filters every event per subscriber.
func (s *Service) requestKey(r *http.Request) (key string, principalOnly bool) {
	if strings.Contains(r.Pattern, "/subscribe/") {
		return "", true
	}
	key = store.NormalizeKey(r.PathValue("key"))
	if key == "" && r.Method == http.MethodGet {
		return "", true // list
	}
	return key, false
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

// checkSessionAuth checks if request has valid session cookie with appropriate permissions.
// returns (allowed, handled): handled=true means caller should return (either success or error written).
// allowed=false with handled=true means error response was written.
func (s *Service) checkSessionAuth(r *http.Request, key string, needWrite, principalOnly bool,
	w http.ResponseWriter) (allowed, handled bool) {
	for _, cookieName := range cookie.SessionCookieNames {
		c, err := r.Cookie(cookieName)
		if err != nil {
			continue
		}
		username, valid := s.GetSessionUser(r.Context(), c.Value)
		if !valid {
			continue
		}
		if principalOnly {
			return true, true
		}
		// check user permissions for the key
		if !s.CheckUserPermission(username, key, needWrite) {
			log.Printf("[INFO] user %q denied %s access to key %q", username, r.Method, key)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return false, true
		}
		return true, true
	}
	return false, false // no session found
}
