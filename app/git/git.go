// Package git provides git-based versioning for key-value storage.
// It tracks all changes to keys in a local git repository with optional
// push to remote.
package git

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Author represents the author of a git commit.
type Author struct {
	Name  string
	Email string
}

// DefaultAuthor returns the default author for git commits.
func DefaultAuthor() Author {
	return Author{Name: "stash", Email: "stash@localhost"}
}

// Config holds git repository configuration
type Config struct {
	Path   string // local repository path
	Branch string // branch name (default: master)
	Remote string // remote name (optional, for push/pull)
}

// Store provides git-backed versioning for key-value storage
type Store struct {
	cfg  Config
	repo *git.Repository
}

// New creates a new git store, initializing or opening the repository
func New(cfg Config) (*Store, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("git path is required")
	}
	if cfg.Branch == "" {
		cfg.Branch = "master"
	}

	s := &Store{cfg: cfg}
	if err := s.initRepo(); err != nil {
		return nil, fmt.Errorf("failed to init git repo: %w", err)
	}
	return s, nil
}

// initRepo opens existing or creates new git repository
func (s *Store) initRepo() error {
	// try to open existing repo
	repo, err := git.PlainOpen(s.cfg.Path)
	if err == nil {
		s.repo = repo
		return s.ensureBranch()
	}

	// create new repo if not exists
	if errors.Is(err, git.ErrRepositoryNotExists) {
		return s.createNewRepo()
	}

	return fmt.Errorf("failed to open repo: %w", err)
}

// ensureBranch checks out the configured branch, creating it if necessary
func (s *Store) ensureBranch() error {
	wt, err := s.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	branchRef := plumbing.NewBranchReferenceName(s.cfg.Branch)

	// try to checkout existing branch
	if chkErr := wt.Checkout(&git.CheckoutOptions{Branch: branchRef}); chkErr == nil {
		return nil
	}

	// branch doesn't exist, create it from HEAD
	head, headErr := s.repo.Head()
	if headErr != nil {
		return fmt.Errorf("failed to get HEAD: %w", headErr)
	}

	// create and checkout the branch
	if chkErr := wt.Checkout(&git.CheckoutOptions{Branch: branchRef, Hash: head.Hash(), Create: true}); chkErr != nil {
		return fmt.Errorf("failed to checkout branch %s: %w", s.cfg.Branch, chkErr)
	}
	return nil
}

func (s *Store) createNewRepo() error {
	repo, err := git.PlainInit(s.cfg.Path, false)
	if err != nil {
		return fmt.Errorf("failed to init repo: %w", err)
	}
	s.repo = repo

	// create initial commit on configured branch
	wt, wtErr := repo.Worktree()
	if wtErr != nil {
		return fmt.Errorf("failed to get worktree: %w", wtErr)
	}

	// create .gitkeep to have something to commit
	gitkeep := filepath.Join(s.cfg.Path, ".gitkeep")
	if writeErr := os.WriteFile(gitkeep, []byte{}, 0o600); writeErr != nil {
		return fmt.Errorf("failed to create .gitkeep: %w", writeErr)
	}
	if _, addErr := wt.Add(".gitkeep"); addErr != nil {
		return fmt.Errorf("failed to stage .gitkeep: %w", addErr)
	}

	_, commitErr := wt.Commit("initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "stash",
			Email: "stash@localhost",
			When:  time.Now(),
		},
	})
	if commitErr != nil {
		return fmt.Errorf("failed to create initial commit: %w", commitErr)
	}

	// checkout configured branch (create if not master)
	if s.cfg.Branch != "master" {
		head, headErr := repo.Head()
		if headErr != nil {
			return fmt.Errorf("failed to get HEAD: %w", headErr)
		}
		branchRef := plumbing.NewBranchReferenceName(s.cfg.Branch)
		if chkErr := wt.Checkout(&git.CheckoutOptions{
			Branch: branchRef,
			Hash:   head.Hash(),
			Create: true,
		}); chkErr != nil {
			return fmt.Errorf("failed to checkout branch %s: %w", s.cfg.Branch, chkErr)
		}
	}

	return nil
}

// Commit writes key-value to file and commits to git.
// The author parameter specifies who made the change.
func (s *Store) Commit(key string, value []byte, operation string, author Author) error {
	// validate key before any file operations
	if err := s.validateKey(key); err != nil {
		return err
	}

	// convert key to file path with .val suffix
	filePath := keyToPath(key)
	fullPath := filepath.Join(s.cfg.Path, filePath)

	// ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// write file
	if err := os.WriteFile(fullPath, value, 0o600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	// stage file
	wt, err := s.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	if _, addErr := wt.Add(filePath); addErr != nil {
		return fmt.Errorf("failed to stage file: %w", addErr)
	}

	// commit with metadata
	msg := fmt.Sprintf("%s %s\n\ntimestamp: %s\noperation: %s\nkey: %s",
		operation, key, time.Now().Format(time.RFC3339), operation, key)

	_, commitErr := wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{
			Name:  author.Name,
			Email: author.Email,
			When:  time.Now(),
		},
	})
	if commitErr != nil {
		return fmt.Errorf("failed to commit: %w", commitErr)
	}

	return nil
}

// Delete removes key file and commits the deletion.
// The author parameter specifies who made the change.
func (s *Store) Delete(key string, author Author) error {
	// validate key before any file operations
	if err := s.validateKey(key); err != nil {
		return err
	}

	filePath := keyToPath(key)
	fullPath := filepath.Join(s.cfg.Path, filePath)

	// check if file exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return nil // nothing to delete
	}

	// remove file
	if err := os.Remove(fullPath); err != nil {
		return fmt.Errorf("failed to remove file: %w", err)
	}

	// stage deletion
	wt, err := s.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	if _, rmErr := wt.Remove(filePath); rmErr != nil {
		return fmt.Errorf("failed to stage deletion: %w", rmErr)
	}

	// commit deletion
	msg := fmt.Sprintf("delete %s\n\ntimestamp: %s\noperation: delete\nkey: %s", key, time.Now().Format(time.RFC3339), key)
	_, commitErr := wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{
			Name:  author.Name,
			Email: author.Email,
			When:  time.Now(),
		},
	})
	if commitErr != nil {
		return fmt.Errorf("failed to commit deletion: %w", commitErr)
	}

	return nil
}

// Push pushes commits to remote repository
func (s *Store) Push() error {
	if s.cfg.Remote == "" {
		return nil // no remote configured
	}

	err := s.repo.Push(&git.PushOptions{
		RemoteName: s.cfg.Remote,
		RefSpecs: []config.RefSpec{
			config.RefSpec(fmt.Sprintf("refs/heads/%s:refs/heads/%s", s.cfg.Branch, s.cfg.Branch)),
		},
	})
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("failed to push: %w", err)
	}
	return nil
}

// Head returns the current HEAD commit hash as a short string
func (s *Store) Head() (string, error) {
	ref, err := s.repo.Head()
	if err != nil {
		return "", fmt.Errorf("failed to get HEAD: %w", err)
	}
	return ref.Hash().String()[:7], nil
}

// Pull fetches and merges from remote repository
func (s *Store) Pull() error {
	if s.cfg.Remote == "" {
		return nil // no remote configured
	}

	wt, err := s.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	pullErr := wt.Pull(&git.PullOptions{
		RemoteName:    s.cfg.Remote,
		ReferenceName: plumbing.NewBranchReferenceName(s.cfg.Branch),
	})
	if pullErr != nil && !errors.Is(pullErr, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("failed to pull: %w", pullErr)
	}
	return nil
}

// Checkout switches to specified revision (commit, tag, or branch)
func (s *Store) Checkout(rev string) error {
	wt, err := s.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	// try to resolve as branch first
	branchRef := plumbing.NewBranchReferenceName(rev)
	if _, refErr := s.repo.Reference(branchRef, true); refErr == nil {
		if chkErr := wt.Checkout(&git.CheckoutOptions{Branch: branchRef}); chkErr != nil {
			return fmt.Errorf("failed to checkout branch %s: %w", rev, chkErr)
		}
		return nil
	}

	// try to resolve as tag
	tagRef := plumbing.NewTagReferenceName(rev)
	if _, refErr := s.repo.Reference(tagRef, true); refErr == nil {
		if chkErr := wt.Checkout(&git.CheckoutOptions{Branch: tagRef}); chkErr != nil {
			return fmt.Errorf("failed to checkout tag %s: %w", rev, chkErr)
		}
		return nil
	}

	// try to resolve as commit hash
	hash, resolveErr := s.repo.ResolveRevision(plumbing.Revision(rev))
	if resolveErr != nil {
		return fmt.Errorf("failed to resolve revision %s: %w", rev, resolveErr)
	}

	if chkErr := wt.Checkout(&git.CheckoutOptions{Hash: *hash}); chkErr != nil {
		return fmt.Errorf("failed to checkout commit %s: %w", rev, chkErr)
	}
	return nil
}

// ReadAll reads all key-value pairs from the repository
func (s *Store) ReadAll() (map[string][]byte, error) {
	result := make(map[string][]byte)

	walkErr := filepath.Walk(s.cfg.Path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// skip directories and .git folder
		if info.IsDir() {
			if info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		// only process .val files
		if !strings.HasSuffix(path, ".val") {
			return nil
		}

		// read file content - path is validated by Walk to be within s.cfg.Path
		content, readErr := os.ReadFile(path) //nolint:gosec // path is validated by filepath.Walk
		if readErr != nil {
			return fmt.Errorf("failed to read %s: %w", path, readErr)
		}

		// convert path back to key
		relPath, relErr := filepath.Rel(s.cfg.Path, path)
		if relErr != nil {
			return fmt.Errorf("failed to get relative path: %w", relErr)
		}
		key := pathToKey(relPath)
		result[key] = content

		return nil
	})

	if walkErr != nil {
		return nil, fmt.Errorf("failed to walk repository: %w", walkErr)
	}

	return result, nil
}

// keyToPath converts a key to a file path with .val suffix
// e.g., "app/config/db" -> "app/config/db.val"
func keyToPath(key string) string {
	return key + ".val"
}

// validateKey checks if the key is safe (no path traversal).
// returns error if key would escape the repository directory.
func (s *Store) validateKey(key string) error {
	// reject empty keys
	if key == "" {
		return fmt.Errorf("invalid key: empty key not allowed")
	}

	// reject absolute paths
	if strings.HasPrefix(key, "/") {
		return fmt.Errorf("invalid key: absolute path not allowed")
	}

	// reject path traversal sequences
	if strings.Contains(key, "..") {
		return fmt.Errorf("invalid key: path traversal not allowed")
	}

	// double-check: resolved path must be within repo
	filePath := filepath.Join(s.cfg.Path, keyToPath(key))
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return fmt.Errorf("invalid key: failed to resolve path")
	}
	absBase, err := filepath.Abs(s.cfg.Path)
	if err != nil {
		return fmt.Errorf("invalid key: failed to resolve base path")
	}

	if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) {
		return fmt.Errorf("invalid key: path escapes repository")
	}

	return nil
}

// pathToKey converts a file path back to a key
// e.g., "app/config/db.val" -> "app/config/db"
func pathToKey(path string) string {
	return strings.TrimSuffix(path, ".val")
}
