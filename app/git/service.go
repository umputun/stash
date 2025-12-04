package git

import "fmt"

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
}

// NewService creates a new git service.
// if pushSync is true, commits will be followed by pull and push.
func NewService(st Storer, pushSync bool) *Service {
	return &Service{store: st, pushSync: pushSync}
}

// Commit commits a key-value change to git and optionally syncs with remote.
func (s *Service) Commit(req CommitRequest) error {
	if err := s.store.Commit(req); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	if s.pushSync {
		return s.pullAndPush()
	}
	return nil
}

// Delete removes a key from git and optionally syncs with remote.
func (s *Service) Delete(key string, author Author) error {
	if err := s.store.Delete(key, author); err != nil {
		return fmt.Errorf("delete: %w", err)
	}
	if s.pushSync {
		return s.pullAndPush()
	}
	return nil
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
