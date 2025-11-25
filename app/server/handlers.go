package server

import (
	"errors"
	"io"
	"net/http"

	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/store"
)

// handleGet retrieves the value for a key.
// GET /kv/{key...}
func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if key == "" {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusBadRequest, nil, "key is required")
		return
	}

	value, err := s.store.Get(key)
	if errors.Is(err, store.ErrNotFound) {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusNotFound, err, "key not found")
		return
	}
	if err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to get key")
		return
	}

	log.Printf("[DEBUG] get %s (%d bytes)", key, len(value))

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(value); err != nil {
		log.Printf("[WARN] failed to write response: %v", err)
	}
}

// handleSet stores a value for a key.
// PUT /kv/{key...}
// Accepts format via X-Stash-Format header or ?format= query param (defaults to "text").
func (s *Server) handleSet(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
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

	log.Printf("[DEBUG] set %s (%d bytes, format=%s)", key, len(value), format)

	// commit to git if enabled
	s.gitCommit(r, key, value, "set")

	w.WriteHeader(http.StatusOK)
}

// handleDelete removes a key from the store.
// DELETE /kv/{key...}
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
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

	log.Printf("[DEBUG] delete %s", key)

	// delete from git if enabled
	s.gitDelete(r, key)

	w.WriteHeader(http.StatusNoContent)
}

// gitCommit commits a key-value change to git if enabled.
// logs warning on failure but does not fail the API request.
func (s *Server) gitCommit(r *http.Request, key string, value []byte, operation string) {
	if s.gitStore == nil {
		return
	}

	author := s.getAuthorFromRequest(r)
	if err := s.gitStore.Commit(key, value, operation, author); err != nil {
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

// getAuthorFromRequest extracts the git author from request context.
// returns username from session cookie for web UI users, default author otherwise.
func (s *Server) getAuthorFromRequest(r *http.Request) git.Author {
	if s.auth == nil {
		return git.DefaultAuthor()
	}

	// check session cookie for web UI users
	for _, cookieName := range sessionCookieNames {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			continue
		}
		username, valid := s.auth.GetSessionUser(cookie.Value)
		if valid && username != "" {
			return git.Author{Name: username, Email: username + "@stash"}
		}
	}

	// API tokens use default author
	return git.DefaultAuthor()
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
