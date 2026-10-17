package git

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/go-pkgz/lgr"
)

//go:generate moq -out mocks/storer.go -pkg mocks -skip-ensure -fmt goimports . Storer

// Storer defines the interface for git store operations needed by Service.
type Storer interface {
	Commit(req CommitRequest) error
	Delete(key string, author Author) error
	Pull() error
	Push() error
	PushContext(ctx context.Context) error
	History(key string, limit int) ([]HistoryEntry, error)
	GetRevision(key string, rev string) ([]byte, string, error)
}

// pushTimeout bounds one background push; the store lock is held for the push, so writes can
// wait this long while a remote does not answer.
const pushTimeout = 10 * time.Second

// ServiceOpts configures when Service pushes to the remote.
type ServiceOpts struct {
	PushSync     bool          // pull and push inline after each commit (--git.push)
	PushInterval time.Duration // when > 0, push in the background on each commit and on this interval; PushSync is ignored
}

// Service wraps Store and provides orchestrated git operations.
// handles commit + optional pull/push sequence.
type Service struct {
	store   Storer
	opts    ServiceOpts
	mu      sync.Mutex    // orders database writes and their local commits
	signal  chan struct{} // wakes Run after a commit
	pending atomic.Bool   // a commit or a failed push is waiting for a push
}

// NewService creates a new git service.
func NewService(st Storer, opts ServiceOpts) *Service {
	return &Service{store: st, opts: opts, signal: make(chan struct{}, 1)}
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
	if !committed {
		return nil
	}
	if s.opts.PushInterval > 0 {
		s.pending.Store(true)
		select {
		case s.signal <- struct{}{}:
		default:
		}
		return nil
	}
	if s.opts.PushSync {
		if syncErr := s.pullAndPush(); syncErr != nil {
			log.Printf("[WARN] git sync failed: %v", syncErr)
		}
	}
	return nil
}

// Run pushes in the background until ctx is done: once at start, after each commit, and on
// PushInterval ticks while a push is pending. On ctx done it makes a last push when one is
// pending and returns after it. Returns at once when PushInterval is not positive.
func (s *Service) Run(ctx context.Context) {
	if s.opts.PushInterval <= 0 {
		return
	}
	s.push()
	ticker := time.NewTicker(s.opts.PushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if s.pending.Load() {
				s.push()
			}
			return
		case <-s.signal:
			s.push()
		case <-ticker.C:
			if s.pending.Load() {
				s.push()
			}
		}
	}
}

// push makes one bounded push attempt and leaves the push pending when it fails.
func (s *Service) push() {
	s.pending.Store(false)
	ctx, cancel := context.WithTimeout(context.Background(), pushTimeout)
	defer cancel()
	err := s.store.PushContext(ctx)
	if err == nil {
		return
	}
	s.pending.Store(true)
	if s.isRejected(err) {
		log.Printf("[ERROR] git push rejected, remote branch moved, another writer on the branch? %v", err)
		return
	}
	log.Printf("[WARN] git push failed, will retry: %v", err)
}

// isRejected reports a non-fast-forward push; go-git has no sentinel error for it.
func (s *Service) isRejected(err error) bool {
	return strings.Contains(err.Error(), "non-fast-forward update")
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
