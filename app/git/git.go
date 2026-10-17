// Package git provides git-based versioning for key-value storage.
// It tracks all changes to keys in a local git repository with optional
// push to remote.
package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	log "github.com/go-pkgz/lgr"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"golang.org/x/net/proxy"

	"github.com/umputun/stash/app/store"
	"github.com/umputun/stash/lib/stash"
)

const defaultBranch = "master"

// Author represents the author of a git commit.
type Author struct {
	Name  string
	Email string
}

// DefaultAuthor returns the default author for git commits.
func DefaultAuthor() Author {
	return Author{Name: "stash", Email: "stash@localhost"}
}

// KeyValue holds a key's value and format metadata.
type KeyValue struct {
	Value  []byte
	Format string
}

// HistoryEntry represents a single revision of a key.
type HistoryEntry struct {
	Hash      string    `json:"hash"`
	Timestamp time.Time `json:"timestamp"`
	Author    string    `json:"author"`
	Operation string    `json:"operation"`
	Format    string    `json:"format"`
	Value     []byte    `json:"value"`
}

// CommitRequest holds parameters for a git commit operation.
type CommitRequest struct {
	Key       string
	Value     []byte
	Operation string
	Format    string
	Author    Author
}

// Config holds git repository configuration
type Config struct {
	Path      string    // local repository path
	Branch    string    // branch name (default: master)
	Remote    string    // remote name (optional, for push/pull; "origin" when URL is set)
	URL       string    // remote URL (optional); the local repository is cloned from it and kept in step
	SSHKey    string    // path to SSH private key (optional, for clone, push and pull)
	Encryptor Encryptor // encrypts secret values in the repository (optional)
}

// the mock lives in this package because mocks/ imports git for the Storer mock and an internal
// test cannot import it back
//go:generate moq -out encryptor_mock_test.go -pkg git -skip-ensure -fmt goimports . Encryptor

// Encryptor encrypts secret values before they are written to the repository and decrypts
// them on the way back.
type Encryptor interface {
	Encrypt(value []byte) ([]byte, error)
	Decrypt(encrypted []byte) ([]byte, error)
}

// encPrefix marks a repository value encrypted by the Encryptor. Values without it are
// plaintext written before encryption was introduced.
const encPrefix = "$ENC$"

// Store provides git-backed versioning for key-value storage
type Store struct {
	cfg     Config
	repo    *git.Repository
	mu      sync.Mutex
	decrypt chan struct{} // bounds concurrent decryptions, each an argon2 derivation at 64 MiB
}

// maxConcurrentDecrypt caps argon2 derivations in flight across history and revision reads.
const maxConcurrentDecrypt = 4

// New creates a new git store, initializing or opening the repository
func New(cfg Config) (*Store, error) {
	if cfg.Path == "" {
		return nil, errors.New("git path is required")
	}
	if cfg.Branch == "" {
		cfg.Branch = defaultBranch
	}
	if cfg.URL != "" && cfg.Remote == "" {
		cfg.Remote = "origin"
	}

	s := &Store{cfg: cfg, decrypt: make(chan struct{}, maxConcurrentDecrypt)}
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
		if s.cfg.URL != "" {
			return s.openRemoteCopy()
		}
		return s.ensureBranch()
	}

	if !errors.Is(err, git.ErrRepositoryNotExists) {
		return fmt.Errorf("failed to open repo: %w", err)
	}
	if s.cfg.URL != "" {
		return s.cloneRemote()
	}
	return s.createNewRepo()
}

// cloneRemote clones the configured branch from URL. An empty remote gets a fresh local
// repository with the remote added, so the first push creates the branch.
func (s *Store) cloneRemote() error {
	auth, err := s.auth(s.cfg.URL)
	if err != nil {
		return err
	}
	repo, err := git.PlainClone(s.cfg.Path, false, &git.CloneOptions{
		URL: s.cfg.URL, RemoteName: s.cfg.Remote, Auth: auth,
		ReferenceName: plumbing.NewBranchReferenceName(s.cfg.Branch), SingleBranch: true,
	})
	if errors.Is(err, transport.ErrEmptyRemoteRepository) {
		if initErr := s.createNewRepo(); initErr != nil {
			return initErr
		}
		return s.ensureRemote()
	}
	if err != nil {
		return fmt.Errorf("failed to clone branch %q from %s: %w", s.cfg.Branch, s.cfg.URL, err)
	}
	s.repo = repo
	return nil
}

// openRemoteCopy prepares an existing local copy of the remote: the remote must point to URL,
// and the worktree is forced back to the local branch head. That drops what an interrupted
// commit left behind and a detached HEAD left by restore, and keeps commits not yet pushed.
func (s *Store) openRemoteCopy() error {
	if err := s.ensureRemote(); err != nil {
		return err
	}
	wt, err := s.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}
	branchRef := plumbing.NewBranchReferenceName(s.cfg.Branch)
	if _, refErr := s.repo.Reference(branchRef, true); refErr != nil {
		// creating the branch from the local HEAD would graft unrelated history onto it
		return fmt.Errorf("local repository %s has no branch %q; remove it to clone the branch from %s",
			s.cfg.Path, s.cfg.Branch, s.cfg.URL)
	}
	if err := wt.Checkout(&git.CheckoutOptions{Branch: branchRef, Force: true}); err != nil {
		return fmt.Errorf("failed to checkout branch %s: %w", s.cfg.Branch, err)
	}
	if err := wt.Reset(&git.ResetOptions{Mode: git.HardReset}); err != nil {
		return fmt.Errorf("failed to reset to branch %s: %w", s.cfg.Branch, err)
	}
	return nil
}

// ensureRemote adds the remote pointing to URL when missing and refuses one pointing elsewhere.
func (s *Store) ensureRemote() error {
	rem, err := s.repo.Remote(s.cfg.Remote)
	if errors.Is(err, git.ErrRemoteNotFound) {
		if _, addErr := s.repo.CreateRemote(&config.RemoteConfig{Name: s.cfg.Remote, URLs: []string{s.cfg.URL}}); addErr != nil {
			return fmt.Errorf("failed to add remote %s: %w", s.cfg.Remote, addErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read remote %s: %w", s.cfg.Remote, err)
	}
	// go-git fetches from the first url and pushes to the last, so only a single matching url is safe
	if urls := rem.Config().URLs; len(urls) != 1 || urls[0] != s.cfg.URL {
		return fmt.Errorf("remote %s points to %v, not %s", s.cfg.Remote, urls, s.cfg.URL)
	}
	return nil
}

// auth returns the SSH key auth for remoteURL, nil without a configured key (go-git then
// falls back to ssh-agent for SSH remotes).
func (s *Store) auth(remoteURL string) (transport.AuthMethod, error) {
	if s.cfg.SSHKey == "" {
		return nil, nil //nolint:nilnil // no key configured is a valid state
	}
	keys, err := ssh.NewPublicKeysFromFile(s.sshUser(remoteURL), s.cfg.SSHKey, "")
	if err != nil {
		return nil, fmt.Errorf("failed to load SSH key: %w", err)
	}
	return keys, nil
}

// sshUser returns the user named in an SSH remote URL, "git" when it names none.
func (s *Store) sshUser(remoteURL string) string {
	ep, err := transport.NewEndpoint(remoteURL)
	if err != nil || ep.User == "" || (ep.Protocol != "ssh" && ep.Protocol != "") {
		return "git"
	}
	return ep.User
}

// remoteURL returns the URL of the configured remote, empty when it has none.
func (s *Store) remoteURL() string {
	if s.cfg.URL != "" {
		return s.cfg.URL
	}
	rem, err := s.repo.Remote(s.cfg.Remote)
	if err != nil || len(rem.Config().URLs) == 0 {
		return ""
	}
	return rem.Config().URLs[0]
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
	if s.cfg.Branch != defaultBranch {
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

// writeKeyFile writes key value to file and returns the relative path for staging.
// The write is confined to the repository: a symlink in a checkout pointing outside it,
// or an absolute link, is refused rather than followed.
func (s *Store) writeKeyFile(key string, value []byte) (string, error) {
	filePath := s.keyToPath(key)

	root, err := os.OpenRoot(s.cfg.Path)
	if err != nil {
		return "", fmt.Errorf("failed to open repository: %w", err)
	}
	defer root.Close()

	if err := root.MkdirAll(filepath.Dir(filePath), 0o750); err != nil {
		return "", fmt.Errorf("failed to create directory: %w", err)
	}
	if err := root.WriteFile(filePath, value, 0o600); err != nil {
		return "", fmt.Errorf("failed to write file: %w", err)
	}
	return filePath, nil
}

// encodeValue prepares a value for the repository: secret values are encrypted and marked
// with encPrefix. ZK blobs are already opaque and pass through unchanged.
func (s *Store) encodeValue(key string, value []byte) ([]byte, error) {
	if s.cfg.Encryptor == nil || !store.IsSecret(key) || stash.IsZKEncrypted(value) {
		return value, nil
	}
	encrypted, err := s.cfg.Encryptor.Encrypt(value)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt %q: %w", key, err)
	}
	return append([]byte(encPrefix), encrypted...), nil
}

// decodeValue reverses encodeValue. Only secret keys are inspected, so an ordinary value that
// happens to start with encPrefix is left alone. A marked value with no encryptor, the wrong
// key or a damaged payload is an error, never returned as data.
func (s *Store) decodeValue(key string, value []byte) ([]byte, error) {
	if !store.IsSecret(key) || !bytes.HasPrefix(value, []byte(encPrefix)) {
		return value, nil
	}
	if s.cfg.Encryptor == nil {
		return nil, fmt.Errorf("%q is encrypted in the repository but no secrets key is configured", key)
	}
	s.decrypt <- struct{}{}
	defer func() { <-s.decrypt }()
	decrypted, err := s.cfg.Encryptor.Decrypt(value[len(encPrefix):])
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt %q: %w", key, err)
	}
	return decrypted, nil
}

// Commit writes key-value to file and commits to git.
func (s *Store) Commit(req CommitRequest) error {
	if err := s.validateKey(req.Key); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commitLocked(req)
}

// commitLocked is Commit for a caller that holds s.mu and has validated the key.
func (s *Store) commitLocked(req CommitRequest) error {
	now := time.Now()

	format := req.Format
	if format == "" {
		format = "text"
	}

	value, err := s.encodeValue(req.Key, req.Value)
	if err != nil {
		return err
	}
	filePath, err := s.writeKeyFile(req.Key, value)
	if err != nil {
		return err
	}

	wt, err := s.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	if _, addErr := wt.Add(filePath); addErr != nil {
		return fmt.Errorf("failed to stage file: %w", addErr)
	}

	// commit with metadata including format
	msg := fmt.Sprintf("%s %s\n\ntimestamp: %s\noperation: %s\nkey: %s\nformat: %s",
		req.Operation, req.Key, now.Format(time.RFC3339), req.Operation, req.Key, format)

	opts := &git.CommitOptions{Author: &object.Signature{Name: req.Author.Name, Email: req.Author.Email, When: now}}
	_, commitErr := wt.Commit(msg, opts)
	if errors.Is(commitErr, git.ErrEmptyCommit) {
		// the value is unchanged; format lives only in the commit message, so a format change
		// still needs a commit of its own
		if s.getFileFormat(req.Key) == format {
			return nil
		}
		opts.AllowEmptyCommits = true
		_, commitErr = wt.Commit(msg, opts)
	}
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

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(key, author)
}

// deleteLocked is Delete for a caller that holds s.mu and has validated the key.
func (s *Store) deleteLocked(key string, author Author) error {
	now := time.Now()
	filePath := s.keyToPath(key)

	root, err := os.OpenRoot(s.cfg.Path)
	if err != nil {
		return fmt.Errorf("failed to open repository: %w", err)
	}
	defer root.Close()

	// check if file exists
	if _, statErr := root.Lstat(filePath); os.IsNotExist(statErr) {
		return nil // nothing to delete
	}

	// remove file
	if rmErr := root.Remove(filePath); rmErr != nil {
		return fmt.Errorf("failed to remove file: %w", rmErr)
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
	msg := fmt.Sprintf("delete %s\n\ntimestamp: %s\noperation: delete\nkey: %s", key, now.Format(time.RFC3339), key)
	_, commitErr := wt.Commit(msg, &git.CommitOptions{
		Author: &object.Signature{
			Name:  author.Name,
			Email: author.Email,
			When:  now,
		},
	})
	if commitErr != nil {
		return fmt.Errorf("failed to commit deletion: %w", commitErr)
	}

	return nil
}

// Push pushes commits to remote repository
func (s *Store) Push() error {
	return s.PushContext(context.Background())
}

// PushContext pushes the branch to the remote, giving up when ctx is done.
func (s *Store) PushContext(ctx context.Context) error {
	if s.cfg.Remote == "" {
		return nil // no remote configured
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	remoteURL := s.remoteURL()
	auth, err := s.auth(remoteURL)
	if err != nil {
		return err
	}

	opts := &git.PushOptions{
		RemoteName: s.cfg.Remote,
		Auth:       auth,
		RefSpecs: []config.RefSpec{
			config.RefSpec(fmt.Sprintf("refs/heads/%s:refs/heads/%s", s.cfg.Branch, s.cfg.Branch)),
		},
	}
	// go-git dials ssh and runs its handshake without the context, so a remote that accepts and
	// never answers would hold s.mu forever; the deadline reaches the connection through a proxy dialer
	if deadline, ok := ctx.Deadline(); ok && s.isSSH(remoteURL) {
		registerDeadlineDialer.Do(func() { proxy.RegisterDialerType(deadlineScheme, newDeadlineDialer) })
		opts.ProxyOptions = transport.ProxyOptions{URL: fmt.Sprintf("%s://push?deadline=%d", deadlineScheme, deadline.UnixNano())}
	}

	err = s.repo.PushContext(ctx, opts)
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("failed to push: %w", err)
	}
	return nil
}

// isSSH reports whether remoteURL is reached over ssh.
func (s *Store) isSSH(remoteURL string) bool {
	ep, err := transport.NewEndpoint(remoteURL)
	return err == nil && ep.Protocol == "ssh"
}

// deadlineScheme is the proxy scheme PushContext routes ssh pushes through.
const deadlineScheme = "stash-deadline"

// registerDeadlineDialer registers deadlineScheme once; the proxy registry is not safe for concurrent writes.
var registerDeadlineDialer sync.Once

// newDeadlineDialer builds a deadlineDialer from a deadlineScheme URL carrying the deadline in Unix nanoseconds.
func newDeadlineDialer(u *url.URL, _ proxy.Dialer) (proxy.Dialer, error) {
	ns, err := strconv.ParseInt(u.Query().Get("deadline"), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid push deadline in %q: %w", u, err)
	}
	return deadlineDialer{deadline: time.Unix(0, ns)}, nil
}

// deadlineDialer dials through the environment's proxy settings, as go-git does without one, and
// sets the deadline on the connection so the handshake and the transfer end with it.
type deadlineDialer struct {
	deadline time.Time
}

// Dial dials addr bounded by the deadline.
func (d deadlineDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

// DialContext dials addr bounded by ctx and the deadline, and sets the deadline on the connection.
func (d deadlineDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ctx, cancel := context.WithDeadline(ctx, d.deadline)
	defer cancel()
	conn, err := proxy.Dial(ctx, network, addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	if err := conn.SetDeadline(d.deadline); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("set deadline on %s: %w", addr, err)
	}
	return conn, nil
}

// Head returns the current HEAD commit hash as a short string
func (s *Store) Head() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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

	s.mu.Lock()
	defer s.mu.Unlock()

	auth, err := s.auth(s.remoteURL())
	if err != nil {
		return err
	}

	wt, err := s.repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	pullErr := wt.Pull(&git.PullOptions{
		RemoteName:    s.cfg.Remote,
		Auth:          auth,
		ReferenceName: plumbing.NewBranchReferenceName(s.cfg.Branch),
	})
	if pullErr != nil && !errors.Is(pullErr, git.NoErrAlreadyUpToDate) {
		return fmt.Errorf("failed to pull: %w", pullErr)
	}
	return nil
}

// Checkout switches to specified revision (commit, tag, or branch)
func (s *Store) Checkout(rev string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

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

// ReadAll reads all key-value pairs of the HEAD commit with their formats, so uncommitted
// worktree changes are ignored. Format comes from the newest commit for each key, "text" when
// that commit has none.
func (s *Store) ReadAll() (map[string]KeyValue, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, err := s.headTree()
	if err != nil {
		return nil, err
	}
	formats := s.keyFormats()

	result := make(map[string]KeyValue, len(stored))
	for key, content := range stored {
		value, decErr := s.decodeValue(key, content)
		if decErr != nil {
			return nil, decErr
		}
		format, ok := formats[key]
		if !ok {
			format = "text"
		}
		result[key] = KeyValue{Value: value, Format: format}
	}
	return result, nil
}

// SyncResult describes what Sync changed.
type SyncResult struct {
	Updated int // keys committed with a new value or format
	Deleted int // keys removed because the database no longer has them
	Skipped int // keys whose file name the filesystem cannot hold
}

// Sync commits the differences between want, the full set of database values, and the HEAD tree,
// one commit per key authored by DefaultAuthor. Keys the repository cannot hold (see validateKey)
// are left alone on both sides, and a key whose file name is too long for the filesystem is skipped.
// A stored value that cannot be decoded is overwritten with want's; a stored key absent from want is
// deleted without decoding it.
func (s *Store) Sync(want map[string]KeyValue) (SyncResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, err := s.headTree()
	if err != nil {
		return SyncResult{}, err
	}
	formats := s.keyFormats()

	var skipped []string
	keep := map[string]bool{} // stored files a skipped key may own
	for key := range want {
		if s.validateKey(key) != nil {
			skipped = append(skipped, fmt.Sprintf("%q", key))
			keep[s.storedKey(key)] = true
		}
	}
	if len(skipped) > 0 {
		slices.Sort(skipped)
		log.Printf("[WARN] git sync skipped keys the repository cannot hold: %s", strings.Join(skipped, ", "))
	}

	var res SyncResult
	for _, key := range slices.Sorted(maps.Keys(stored)) {
		if _, ok := want[key]; ok || keep[key] || s.validateKey(key) != nil {
			continue
		}
		if err := s.deleteLocked(key, DefaultAuthor()); err != nil {
			return res, fmt.Errorf("sync delete %q: %w", key, err)
		}
		res.Deleted++
	}

	for _, key := range slices.Sorted(maps.Keys(want)) {
		if s.validateKey(key) != nil {
			continue
		}
		kv := want[key]
		if kv.Format == "" {
			kv.Format = "text"
		}
		// a stored value that does not decode, such as a secret encrypted with a rotated-out key,
		// is replaced by the database value rather than stopping the sync
		if content, ok := stored[key]; ok {
			current, decErr := s.decodeValue(key, content)
			format, found := formats[key]
			if !found {
				format = "text"
			}
			if decErr == nil && bytes.Equal(current, kv.Value) && format == kv.Format {
				continue
			}
		}
		req := CommitRequest{Key: key, Value: kv.Value, Operation: "sync", Format: kv.Format, Author: DefaultAuthor()}
		err := s.commitLocked(req)
		if errors.Is(err, syscall.ENAMETOOLONG) {
			// the value file is written before staging, so nothing of this key reaches the next commit
			log.Printf("[WARN] git sync skipped %q: its file name is too long for the filesystem", key)
			res.Skipped++
			continue
		}
		if err != nil {
			return res, fmt.Errorf("sync %q: %w", key, err)
		}
		res.Updated++
	}
	return res, nil
}

// headTree returns the stored value of every key in the HEAD commit, as written to the
// repository. Symlinks and files without the .val suffix are not values.
func (s *Store) headTree() (map[string][]byte, error) {
	ref, err := s.repo.Head()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD: %w", err)
	}
	commit, err := s.repo.CommitObject(ref.Hash())
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get HEAD tree: %w", err)
	}

	result := map[string][]byte{}
	err = tree.Files().ForEach(func(f *object.File) error {
		if !strings.HasSuffix(f.Name, ".val") || f.Mode == filemode.Symlink {
			return nil
		}
		content, readErr := f.Contents()
		if readErr != nil {
			return fmt.Errorf("failed to read %s: %w", f.Name, readErr)
		}
		result[s.pathToKey(f.Name)] = []byte(content)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to read HEAD tree: %w", err)
	}
	return result, nil
}

// History returns commit history for a key (newest first).
// limit specifies maximum number of entries to return (0 = unlimited).
func (s *Store) History(key string, limit int) ([]HistoryEntry, error) {
	if err := s.validateKey(key); err != nil {
		return nil, err
	}

	entries, err := s.rawHistory(key, limit)
	if err != nil {
		return nil, err
	}

	// decryption derives a key per revision (argon2, 64 MiB each), so it runs outside the lock
	// that every commit, delete, push and pull takes
	for i := range entries {
		value, decErr := s.decodeValue(key, entries[i].Value)
		if decErr != nil {
			return nil, fmt.Errorf("revision %s: %w", entries[i].Hash, decErr)
		}
		entries[i].Value = value
	}
	return entries, nil
}

// rawHistory reads the commit log for a key under the store lock, values as stored.
func (s *Store) rawHistory(key string, limit int) ([]HistoryEntry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	filePath, want := path.Clean(s.keyToPath(key)), s.storedKey(key)

	// commits are selected by their key: line, not by changed file, so format-only commits,
	// which change no file, are part of the history
	logIter, err := s.repo.Log(&git.LogOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get log: %w", err)
	}
	defer logIter.Close()

	var entries []HistoryEntry
	count := 0

	for limit <= 0 || count < limit {
		commit, iterErr := logIter.Next()
		if iterErr != nil {
			if errors.Is(iterErr, io.EOF) {
				break // normal end of history
			}
			// log unexpected errors but continue with partial results
			log.Printf("[WARN] git history iteration error for key %q: %v", key, iterErr)
			break
		}
		if s.storedKey(s.parseKeyFromCommit(commit.Message)) != want {
			continue
		}

		// extract metadata from commit
		entry := HistoryEntry{
			Hash:      commit.Hash.String()[:7],
			Timestamp: commit.Author.When,
			Author:    commit.Author.Name,
			Operation: s.parseOperationFromCommit(commit.Message),
			Format:    s.parseFormatFromCommit(commit.Message),
		}

		// get file content at this commit (may be missing for delete commits)
		entry.Value = s.getFileContentAtCommit(commit, filePath)

		entries = append(entries, entry)
		count++
	}

	return entries, nil
}

// getFileContentAtCommit retrieves file content at a specific commit.
// returns nil if file doesn't exist (expected for delete commits).
func (s *Store) getFileContentAtCommit(commit *object.Commit, filePath string) []byte {
	tree, treeErr := commit.Tree()
	if treeErr != nil {
		log.Printf("[DEBUG] git history: failed to get tree at %s for %q: %v", commit.Hash, filePath, treeErr)
		return nil
	}

	file, fileErr := tree.File(filePath)
	if fileErr != nil {
		return nil // file not found is expected for delete commits
	}

	content, contentErr := file.Contents()
	if contentErr != nil {
		log.Printf("[DEBUG] git history: failed to read content at %s for %q: %v", commit.Hash, filePath, contentErr)
		return nil
	}

	return []byte(content)
}

// GetRevision returns value and format at specific revision.
func (s *Store) GetRevision(key, rev string) ([]byte, string, error) {
	if err := s.validateKey(key); err != nil {
		return nil, "", err
	}

	content, format, err := s.rawRevision(key, rev)
	if err != nil {
		return nil, "", err
	}

	// decryption runs outside the store lock, as in History
	value, err := s.decodeValue(key, content)
	if err != nil {
		return nil, "", err
	}
	return value, format, nil
}

// rawRevision reads the stored value and format at a revision under the store lock.
func (s *Store) rawRevision(key, rev string) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	filePath := s.keyToPath(key)

	// resolve revision to commit hash
	hash, err := s.repo.ResolveRevision(plumbing.Revision(rev))
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve revision %s: %w", rev, err)
	}

	// get commit object
	commit, err := s.repo.CommitObject(*hash)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get commit: %w", err)
	}

	// get file tree at commit
	tree, err := commit.Tree()
	if err != nil {
		return nil, "", fmt.Errorf("failed to get tree: %w", err)
	}

	// get file content
	file, err := tree.File(filePath)
	if err != nil {
		return nil, "", fmt.Errorf("file not found at revision %s: %w", rev, err)
	}

	content, err := file.Contents()
	if err != nil {
		return nil, "", fmt.Errorf("failed to read file: %w", err)
	}

	return []byte(content), s.parseFormatFromCommit(commit.Message), nil
}

// getFileFormat returns the format from the newest commit for key, "text" if there is none.
func (s *Store) getFileFormat(key string) string {
	logIter, err := s.repo.Log(&git.LogOptions{})
	if err != nil {
		return "text"
	}
	defer logIter.Close()

	format, want := "text", s.storedKey(key)
	_ = logIter.ForEach(func(commit *object.Commit) error {
		if s.storedKey(s.parseKeyFromCommit(commit.Message)) != want {
			return nil
		}
		format = s.parseFormatFromCommit(commit.Message)
		return storer.ErrStop
	})
	return format
}

// keyFormats returns the format of every stored key from its newest commit, in one log walk.
func (s *Store) keyFormats() map[string]string {
	formats := map[string]string{}
	logIter, err := s.repo.Log(&git.LogOptions{})
	if err != nil {
		return formats
	}
	defer logIter.Close()

	_ = logIter.ForEach(func(commit *object.Commit) error {
		key := s.parseKeyFromCommit(commit.Message)
		if key == "" {
			return nil
		}
		key = s.storedKey(key)
		if _, seen := formats[key]; !seen {
			formats[key] = s.parseFormatFromCommit(commit.Message)
		}
		return nil
	})
	return formats
}

// storedKey returns the key as ReadAll derives it from the stored file. go-git cleans the path
// it stages, so keys such as a//b and a/b share one file and one identity; empty stays empty.
func (s *Store) storedKey(key string) string {
	if key == "" {
		return ""
	}
	return s.pathToKey(path.Clean(s.keyToPath(key)))
}

// parseKeyFromCommit extracts the key from the "key: <value>" line of a commit message,
// empty if there is none.
func (s *Store) parseKeyFromCommit(message string) string {
	for line := range strings.SplitSeq(message, "\n") {
		if key, found := strings.CutPrefix(line, "key: "); found {
			return key
		}
	}
	return ""
}

// parseFormatFromCommit extracts format value from commit message metadata.
// looks for "format: <value>" line in commit message, returns "text" if not found.
func (s *Store) parseFormatFromCommit(message string) string {
	for line := range strings.SplitSeq(message, "\n") {
		if format, found := strings.CutPrefix(line, "format: "); found {
			return format
		}
	}
	return "text"
}

// parseOperationFromCommit extracts operation from commit message metadata.
// looks for "operation: <value>" line, or parses first word of commit message.
func (s *Store) parseOperationFromCommit(message string) string {
	for line := range strings.SplitSeq(message, "\n") {
		if op, found := strings.CutPrefix(line, "operation: "); found {
			return op
		}
	}
	// fallback: first word of commit message (e.g., "set", "delete")
	if parts := strings.Fields(message); len(parts) > 0 {
		return parts[0]
	}
	return "unknown"
}

// keyToPath converts a key to a file path with .val suffix
// e.g., "app/config/db" -> "app/config/db.val"
func (s *Store) keyToPath(key string) string {
	return key + ".val"
}

// validateKey checks if the key is safe (no path traversal).
// returns error if key would escape the repository directory.
func (s *Store) validateKey(key string) error {
	// reject empty keys
	if key == "" {
		return errors.New("invalid key: empty key not allowed")
	}

	// reject absolute paths
	if strings.HasPrefix(key, "/") {
		return errors.New("invalid key: absolute path not allowed")
	}

	// reject path traversal sequences
	if strings.Contains(key, "..") {
		return errors.New("invalid key: path traversal not allowed")
	}

	// a newline would let a key forge the key: and format: lines of a commit message
	if strings.IndexFunc(key, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return errors.New("invalid key: control characters not allowed")
	}

	// mirrors go-git's worktree path rules, which refuse these at staging after the file is written;
	// "." would also make two keys share one file. The last part always ends in .val
	parts := strings.Split(s.keyToPath(key), "/")
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || strings.EqualFold(part, ".git") {
			return fmt.Errorf("invalid key: path component %q not allowed", part)
		}
	}

	// double-check: resolved path must be within repo
	filePath := filepath.Join(s.cfg.Path, s.keyToPath(key))
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return errors.New("invalid key: failed to resolve path")
	}
	absBase, err := filepath.Abs(s.cfg.Path)
	if err != nil {
		return errors.New("invalid key: failed to resolve base path")
	}

	if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) {
		return errors.New("invalid key: path escapes repository")
	}

	return nil
}

// pathToKey converts a file path back to a key
// e.g., "app/config/db.val" -> "app/config/db"
func (s *Store) pathToKey(relPath string) string {
	return strings.TrimSuffix(relPath, ".val")
}
