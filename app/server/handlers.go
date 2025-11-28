package server

import (
	"errors"
	"io"
	"net/http"
	"strings"

	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/store"
)

// handleList returns all keys the caller has read access to.
// GET /kv
// Optional query params: ?prefix=app/config (filter by prefix)
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	keys, err := s.store.List()
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to list keys")
		return
	}

	// extract key names for filtering
	keyNames := make([]string, len(keys))
	for i, k := range keys {
		keyNames[i] = k.Key
	}

	// filter by auth permissions
	filteredNames := s.filterKeysByAuth(r, keyNames)
	if filteredNames == nil {
		// no valid auth, but this shouldn't happen since tokenAuth middleware already checked
		rest.SendErrorJSON(w, r, log.Default(), http.StatusUnauthorized, nil, "unauthorized")
		return
	}

	// convert filtered names back to KeyInfo slice
	nameSet := make(map[string]bool, len(filteredNames))
	for _, name := range filteredNames {
		nameSet[name] = true
	}
	filtered := make([]store.KeyInfo, 0, len(filteredNames))
	for _, k := range keys {
		if nameSet[k.Key] {
			filtered = append(filtered, k)
		}
	}

	// filter by prefix if specified
	prefix := r.URL.Query().Get("prefix")
	if prefix != "" {
		var prefixed []store.KeyInfo
		for _, k := range filtered {
			if strings.HasPrefix(k.Key, prefix) {
				prefixed = append(prefixed, k)
			}
		}
		filtered = prefixed
	}

	log.Printf("[DEBUG] list keys: %d found, %d after auth filter", len(keys), len(filtered))
	rest.RenderJSON(w, filtered)
}

// filterKeysByAuth filters keys based on the caller's auth credentials.
// returns nil if auth is required but caller has no valid credentials.
// priority: session cookie > Bearer token > public ACL
func (s *Server) filterKeysByAuth(r *http.Request, keys []string) []string {
	// no auth = return all keys
	if s.auth == nil || !s.auth.Enabled() {
		return keys
	}

	// check session cookie first (authenticated user has priority over public)
	for _, cookieName := range sessionCookieNames {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			continue
		}
		username, valid := s.auth.GetSessionUser(cookie.Value)
		if valid {
			return s.auth.FilterUserKeys(username, keys)
		}
	}

	// check Bearer token (authenticated token has priority over public)
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if filtered := s.auth.FilterTokenKeys(token, keys); filtered != nil {
			return filtered
		}
	}

	// fall back to public access for unauthenticated requests
	if filtered := s.auth.FilterPublicKeys(keys); filtered != nil {
		return filtered
	}

	return nil // no valid auth
}

// handleGet retrieves the value for a key.
// GET /kv/{key...}
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	key := normalizeKey(r.PathValue("key"))
	if key == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "key is required")
		return
	}

	value, format, err := s.store.GetWithFormat(key)
	if errors.Is(err, store.ErrNotFound) {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusNotFound, err, "key not found")
		return
	}
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to get key")
		return
	}

	log.Printf("[DEBUG] get %s (%d bytes, format=%s)", key, len(value), format)

	w.Header().Set("Content-Type", s.formatToContentType(format))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(value); err != nil {
		log.Printf("[WARN] failed to write response: %v", err)
	}
}

// formatToContentType maps storage format to HTTP Content-Type.
func (s *Server) formatToContentType(format string) string {
	switch format {
	case "json":
		return "application/json"
	case "yaml":
		return "application/yaml"
	case "xml":
		return "application/xml"
	case "toml":
		return "application/toml"
	case "hcl", "ini", "text":
		return "text/plain"
	case "shell":
		return "text/x-shellscript"
	default:
		return "application/octet-stream"
	}
}

// handleSet stores a value for a key.
// PUT /kv/{key...}
// Accepts format via X-Stash-Format header or ?format= query param (defaults to "text").
func (s *Server) handleSet(w http.ResponseWriter, r *http.Request) {
	key := normalizeKey(r.PathValue("key"))
	if key == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "key is required")
		return
	}

	value, err := io.ReadAll(r.Body)
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, err, "failed to read body")
		return
	}

	// get format from header or query param, default to "text"
	format := r.Header.Get("X-Stash-Format")
	if format == "" {
		format = r.URL.Query().Get("format")
	}
	if !s.highlighter.IsValidFormat(format) {
		format = "text"
	}

	if err := s.store.Set(key, value, format); err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to set key")
		return
	}

	log.Printf("[INFO] set %q (%d bytes, format=%s) by %s", key, len(value), format, s.getIdentityForLog(r))

	// commit to git if enabled
	s.gitCommit(r, key, value, "set", format)

	w.WriteHeader(http.StatusOK)
}

// handleDelete removes a key from the store.
// DELETE /kv/{key...}
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	key := normalizeKey(r.PathValue("key"))
	if key == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "key is required")
		return
	}

	err := s.store.Delete(key)
	if errors.Is(err, store.ErrNotFound) {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusNotFound, err, "key not found")
		return
	}
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to delete key")
		return
	}

	log.Printf("[INFO] delete %q by %s", key, s.getIdentityForLog(r))

	// delete from git if enabled
	s.gitDelete(r, key)

	w.WriteHeader(http.StatusNoContent)
}

// gitCommit commits a key-value change to git if enabled.
// logs warning on failure but does not fail the API request.
func (s *Server) gitCommit(r *http.Request, key string, value []byte, operation, format string) {
	if s.gitStore == nil {
		return
	}

	req := git.CommitRequest{
		Key:       key,
		Value:     value,
		Operation: operation,
		Format:    format,
		Author:    s.getAuthorFromRequest(r),
	}
	if err := s.gitStore.Commit(req); err != nil {
		log.Printf("[WARN] git commit failed for %s: %v", key, err)
		return
	}

	if s.cfg.GitPush {
		s.gitPullAndPush()
	}
}

// gitDelete deletes a key from git if enabled.
// logs warning on failure but does not fail the API request.
func (s *Server) gitDelete(r *http.Request, key string) {
	if s.gitStore == nil {
		return
	}

	author := s.getAuthorFromRequest(r)
	if err := s.gitStore.Delete(key, author); err != nil {
		log.Printf("[WARN] git delete failed for %s: %v", key, err)
		return
	}

	if s.cfg.GitPush {
		s.gitPullAndPush()
	}
}

// identityType represents the type of identity detected from a request.
type identityType int

const (
	identityAnonymous identityType = iota
	identityUser
	identityToken
)

// identity holds information about who made a request.
type identity struct {
	typ  identityType
	name string // username or token prefix
}

// getIdentity extracts identity from request context.
// returns user identity from session cookie, token identity from Authorization header, or anonymous.
func (s *Server) getIdentity(r *http.Request) identity {
	if s.auth == nil {
		return identity{typ: identityAnonymous}
	}

	// check session cookie for web UI users
	for _, cookieName := range sessionCookieNames {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			continue
		}
		if username, valid := s.auth.GetSessionUser(cookie.Value); valid && username != "" {
			return identity{typ: identityUser, name: username}
		}
	}

	// check API token from Authorization header
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if _, ok := s.auth.GetTokenACL(token); ok {
			prefix := token
			if len(prefix) > 8 {
				prefix = prefix[:8]
			}
			return identity{typ: identityToken, name: "token:" + prefix}
		}
	}

	return identity{typ: identityAnonymous}
}

// getAuthorFromRequest extracts the git author from request context.
// returns username from session cookie for web UI users, token prefix for API tokens, default author otherwise.
func (s *Server) getAuthorFromRequest(r *http.Request) git.Author {
	id := s.getIdentity(r)
	switch id.typ {
	case identityUser, identityToken:
		return git.Author{Name: id.name, Email: id.name + "@stash"}
	default:
		return git.DefaultAuthor()
	}
}

// getIdentityForLog returns identity string for audit logging.
// returns "user:xxx" for web UI users, "token:xxx" for API tokens, "anonymous" otherwise.
func (s *Server) getIdentityForLog(r *http.Request) string {
	id := s.getIdentity(r)
	switch id.typ {
	case identityUser:
		return "user:" + id.name
	case identityToken:
		return id.name // already has "token:" prefix
	default:
		return "anonymous"
	}
}

// gitPullAndPush pulls from remote, then pushes local commits.
// if pull fails due to merge conflict, logs instructions for manual resolution.
// note: local commit is already done and preserved even if pull/push fails.
func (s *Server) gitPullAndPush() {
	if err := s.gitStore.Pull(); err != nil {
		log.Printf("[WARN] git pull failed: %v (local commit preserved)", err)
		log.Printf("[WARN] to sync: cd <git-path> && git pull --rebase && git push")
		return
	}

	if err := s.gitStore.Push(); err != nil {
		log.Printf("[WARN] git push failed: %v (local commit preserved)", err)
	}
}
