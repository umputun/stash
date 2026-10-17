package git

import (
	"fmt"
	"log"
	"sync"
)

//go:generate moq -out mocks/storer.go -pkg mocks -skip-ensure -fmt goimports . Storer

// Storer defines the interface for git store operations needed by Service.
type Storer interface {
	Commit(req CommitRequest) error
	Delete(key string, author Author) error
	Pull() error
	Push() error
	History(key string, limit int) ([]HistoryEntry, error)
	GetRevision(key string, rev string) ([]byte, string, error)
}

// Service wraps Store and provides orchestrated git operations.
// handles commit + optional pull/push sequence.
type Service struct {
	store    Storer
	pushSync bool
	mu       sync.Mutex // orders database writes and their local commits
}

// NewService creates a new git service.
// if pushSync is true, commits will be followed by pull and push.
func NewService(st Storer, pushSync bool) *Service {
	return &Service{store: st, pushSync: pushSync}
}

// Record runs write, which applies a change to the database and returns the matching commit
// request, then commits it to git, both under one lock so git records writes in database order.
// Returns write's error unchanged; git failures are logged, since the database is the source of truth.
// A request with Operation "delete" removes the key from git.
func (s *Service) Record(write func() (CommitRequest, error)) error {
	committed, err := s.recordLocked(write)
	if err != nil {
		return err
	}
	if committed && s.pushSync {
		if syncErr := s.pullAndPush(); syncErr != nil {
			log.Printf("[WARN] git sync failed: %v", syncErr)
		}
	}
	return nil
}

// recordLocked runs write and the local commit under the lock and reports whether the commit succeeded.
func (s *Service) recordLocked(write func() (CommitRequest, error)) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	req, err := write()
	if err != nil {
		return false, err
	}

	var gitErr error
	switch req.Operation {
	case "delete":
		gitErr = s.store.Delete(req.Key, req.Author)
	default:
		gitErr = s.store.Commit(req)
	}
	if gitErr != nil {
		log.Printf("[WARN] git %s failed for %s: %v", req.Operation, req.Key, gitErr)
		return false, nil
	}
	return true, nil
}

// pullAndPush pulls from remote, then pushes local commits.
func (s *Service) pullAndPush() error {
	if err := s.store.Pull(); err != nil {
		return fmt.Errorf("pull: %w", err)
	}
	if err := s.store.Push(); err != nil {
		return fmt.Errorf("push: %w", err)
	}
	return nil
}

// History returns commit history for a key.
func (s *Service) History(key string, limit int) ([]HistoryEntry, error) {
	entries, err := s.store.History(key, limit)
	if err != nil {
		return nil, fmt.Errorf("history: %w", err)
	}
	return entries, nil
}

// GetRevision returns value and format at specific revision.
func (s *Service) GetRevision(key, rev string) ([]byte, string, error) {
	value, format, err := s.store.GetRevision(key, rev)
	if err != nil {
		return nil, "", fmt.Errorf("get revision: %w", err)
	}
	return value, format, nil
}
