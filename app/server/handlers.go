package server

import (
	"errors"
	"io"
	"net/http"

	log "github.com/go-pkgz/lgr"
	"github.com/go-pkgz/rest"

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

	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(value); err != nil {
		log.Printf("[WARN] failed to write response: %v", err)
	}
}

// handleSet stores a value for a key.
// PUT /kv/{key...}
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

	if err := s.store.Set(key, value); err != nil {
		rest.SendErrorJSON(w, r, log.Default(), http.StatusInternalServerError, err, "failed to set key")
		return
	}

	// commit to git if enabled
	s.gitCommit(key, value, "set")

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

	// delete from git if enabled
	s.gitDelete(key)

	w.WriteHeader(http.StatusNoContent)
}

// gitCommit commits a key-value change to git if enabled.
// logs warning on failure but does not fail the API request.
func (s *Server) gitCommit(key string, value []byte, operation string) {
	if s.gitStore == nil {
		return
	}

	if err := s.gitStore.Commit(key, value, operation); err != nil {
		log.Printf("[WARN] git commit failed for %s: %v", key, err)
		return
	}

	if s.cfg.GitPush {
		if err := s.gitStore.Push(); err != nil {
			log.Printf("[WARN] git push failed: %v", err)
		}
	}
}

// gitDelete deletes a key from git if enabled.
// logs warning on failure but does not fail the API request.
func (s *Server) gitDelete(key string) {
	if s.gitStore == nil {
		return
	}

	if err := s.gitStore.Delete(key); err != nil {
		log.Printf("[WARN] git delete failed for %s: %v", key, err)
		return
	}

	if s.cfg.GitPush {
		if err := s.gitStore.Push(); err != nil {
			log.Printf("[WARN] git push failed: %v", err)
		}
	}
}
