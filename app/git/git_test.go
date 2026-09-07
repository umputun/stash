package git

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	kvstore "github.com/umputun/stash/app/store"
)

func TestNew(t *testing.T) {
	t.Run("creates new repo", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := Config{Path: filepath.Join(tmpDir, ".history"), Branch: "master"}

		store, err := New(cfg)
		require.NoError(t, err)
		assert.NotNil(t, store)

		// verify .git directory exists
		_, err = os.Stat(filepath.Join(cfg.Path, ".git"))
		assert.NoError(t, err)
	})

	t.Run("opens existing repo", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := Config{Path: filepath.Join(tmpDir, ".history"), Branch: "master"}

		// create repo first
		store1, err := New(cfg)
		require.NoError(t, err)
		require.NotNil(t, store1)

		// open existing repo
		store2, err := New(cfg)
		require.NoError(t, err)
		assert.NotNil(t, store2)
	})

	t.Run("fails with empty path", func(t *testing.T) {
		cfg := Config{Path: "", Branch: "master"}
		_, err := New(cfg)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path is required")
	})

	t.Run("uses default branch", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfg := Config{Path: filepath.Join(tmpDir, ".history")}

		store, err := New(cfg)
		require.NoError(t, err)
		assert.Equal(t, "master", store.cfg.Branch)
	})
}

func TestStore_Commit(t *testing.T) {
	t.Run("commits new key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		req := CommitRequest{
			Key: "app/config/db", Value: []byte("postgres://localhost/db"),
			Operation: "set", Author: DefaultAuthor(),
		}
		require.NoError(t, store.Commit(req))

		// verify file exists
		valFile := filepath.Join(store.cfg.Path, "app", "config", "db.val")
		content, err := os.ReadFile(valFile)
		require.NoError(t, err)
		assert.Equal(t, "postgres://localhost/db", string(content))
	})

	t.Run("commits nested key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		req := CommitRequest{
			Key: "deep/nested/path/key", Value: []byte("value"),
			Operation: "set", Author: DefaultAuthor(),
		}
		require.NoError(t, store.Commit(req))

		valFile := filepath.Join(store.cfg.Path, "deep", "nested", "path", "key.val")
		content, err := os.ReadFile(valFile)
		require.NoError(t, err)
		assert.Equal(t, "value", string(content))
	})

	t.Run("commits binary data", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		binary := []byte{0x00, 0x01, 0xFF, 0xFE}
		err = store.Commit(CommitRequest{
			Key: "binary/key", Value: binary,
			Operation: "set", Author: DefaultAuthor(),
		})
		require.NoError(t, err)

		valFile := filepath.Join(store.cfg.Path, "binary", "key.val")
		content, err := os.ReadFile(valFile)
		require.NoError(t, err)
		assert.Equal(t, binary, content)
	})
}

func TestStore_Delete(t *testing.T) {
	t.Run("deletes existing key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		// create key first
		err = store.Commit(CommitRequest{
			Key: "app/config/db", Value: []byte("value"),
			Operation: "set", Author: DefaultAuthor(),
		})
		require.NoError(t, err)

		// delete key
		err = store.Delete("app/config/db", DefaultAuthor())
		require.NoError(t, err)

		// verify file is deleted
		valFile := filepath.Join(store.cfg.Path, "app", "config", "db.val")
		_, err = os.Stat(valFile)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("handles nonexistent key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		err = store.Delete("nonexistent/key", DefaultAuthor())
		require.NoError(t, err)
	})
}

func TestStore_ReadAll(t *testing.T) {
	t.Run("reads all keys", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		// create multiple keys
		author := DefaultAuthor()
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key1", Value: []byte("value1"),
			Operation: "set", Author: author,
		}))
		require.NoError(t, store.Commit(CommitRequest{
			Key: "app/config/db", Value: []byte("postgres://"),
			Operation: "set", Author: author,
		}))
		require.NoError(t, store.Commit(CommitRequest{
			Key: "app/config/redis", Value: []byte("redis://"),
			Operation: "set", Author: author,
		}))

		// read all
		result, err := store.ReadAll()
		require.NoError(t, err)
		assert.Len(t, result, 3)
		assert.Equal(t, []byte("value1"), result["key1"].Value)
		assert.Equal(t, []byte("postgres://"), result["app/config/db"].Value)
		assert.Equal(t, []byte("redis://"), result["app/config/redis"].Value)
	})

	t.Run("returns empty map for empty repo", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		result, err := store.ReadAll()
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

func TestStore_Checkout(t *testing.T) {
	t.Run("checkout by commit", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		// create first key
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key1", Value: []byte("value1"),
			Operation: "set", Author: DefaultAuthor(),
		}))

		// get commit hash
		head, err := store.repo.Head()
		require.NoError(t, err)
		commitHash := head.Hash().String()

		// create second key
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key2", Value: []byte("value2"),
			Operation: "set", Author: DefaultAuthor(),
		}))

		// checkout first commit
		err = store.Checkout(commitHash)
		require.NoError(t, err)

		// verify only key1 exists
		result, err := store.ReadAll()
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, []byte("value1"), result["key1"].Value)
	})

	t.Run("fails with invalid revision", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		err = store.Checkout("invalid-rev")
		require.Error(t, err)
	})

	t.Run("checkout by branch", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history"), Branch: "master"})
		require.NoError(t, err)

		// create commit on master
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key1", Value: []byte("v1"),
			Operation: "set", Author: DefaultAuthor(),
		}))

		// create develop branch by reopening with different branch
		store2, err := New(Config{Path: filepath.Join(tmpDir, ".history"), Branch: "develop"})
		require.NoError(t, err)
		require.NoError(t, store2.Commit(CommitRequest{
			Key: "key2", Value: []byte("v2"),
			Operation: "set", Author: DefaultAuthor(),
		}))

		// checkout back to master branch by name
		err = store2.Checkout("master")
		require.NoError(t, err)

		// verify we're on master (only key1 should exist)
		result, err := store2.ReadAll()
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Contains(t, result, "key1")
	})

	t.Run("checkout by tag", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		// create a commit
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key1", Value: []byte("v1"),
			Operation: "set", Author: DefaultAuthor(),
		}))

		// get commit hash and create tag
		head, err := store.repo.Head()
		require.NoError(t, err)
		_, err = store.repo.CreateTag("v1.0.0", head.Hash(), nil)
		require.NoError(t, err)

		// create another commit
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key2", Value: []byte("v2"),
			Operation: "set", Author: DefaultAuthor(),
		}))

		// checkout tag
		err = store.Checkout("v1.0.0")
		require.NoError(t, err)

		// verify we're at the tagged commit (only key1 exists)
		result, err := store.ReadAll()
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Contains(t, result, "key1")
	})
}

func TestStore_Push(t *testing.T) {
	t.Run("no-op without remote", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		err = store.Push()
		require.NoError(t, err)
	})

	t.Run("fails with invalid ssh key path", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{
			Path:   filepath.Join(tmpDir, ".history"),
			Remote: "origin",
			SSHKey: "/nonexistent/path/to/key",
		})
		require.NoError(t, err)

		err = store.Push()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load SSH key")
	})

	t.Run("no-op without remote even with ssh key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{
			Path:   filepath.Join(tmpDir, ".history"),
			SSHKey: "/some/key/path",
		})
		require.NoError(t, err)

		// should return nil without attempting to load key since no remote configured
		err = store.Push()
		require.NoError(t, err)
	})
}

func TestStore_Pull(t *testing.T) {
	t.Run("no-op without remote", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		err = store.Pull()
		require.NoError(t, err)
	})

	t.Run("fails with invalid ssh key path", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{
			Path:   filepath.Join(tmpDir, ".history"),
			Remote: "origin",
			SSHKey: "/nonexistent/path/to/key",
		})
		require.NoError(t, err)

		err = store.Pull()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to load SSH key")
	})

	t.Run("no-op without remote even with ssh key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{
			Path:   filepath.Join(tmpDir, ".history"),
			SSHKey: "/some/key/path",
		})
		require.NoError(t, err)

		// should return nil without attempting to load key since no remote configured
		err = store.Pull()
		require.NoError(t, err)
	})
}

func TestStore_PathTraversal(t *testing.T) {
	t.Run("commit rejects invalid keys", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		// various invalid key attempts
		invalidKeys := []string{
			"",                    // empty key
			"../../etc/passwd",    // path traversal
			"../secret",           // parent directory
			"foo/../../secret",    // nested traversal
			"foo/../../../secret", // deep traversal
			"/etc/passwd",         // absolute path
		}

		for _, key := range invalidKeys {
			err = store.Commit(CommitRequest{Key: key, Value: []byte("malicious"), Operation: "set", Author: DefaultAuthor()})
			require.Error(t, err, "should reject key: %q", key)
			assert.Contains(t, err.Error(), "invalid key", "key: %q", key)
		}

		// verify no files were created outside repo
		_, statErr := os.Stat(filepath.Join(tmpDir, "etc"))
		assert.True(t, os.IsNotExist(statErr), "directory should not exist outside repo")
	})

	t.Run("delete rejects invalid keys", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		invalidKeys := []string{
			"",                 // empty key
			"../../etc/passwd", // path traversal
			"../secret",        // parent directory
			"/etc/passwd",      // absolute path
		}

		for _, key := range invalidKeys {
			err = store.Delete(key, DefaultAuthor())
			require.Error(t, err, "should reject key: %q", key)
			assert.Contains(t, err.Error(), "invalid key", "key: %q", key)
		}
	})

	t.Run("allows valid nested keys", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		// these should work fine
		validKeys := []string{
			"app/config/db",
			"deeply/nested/path/to/key",
			"single",
		}

		for _, key := range validKeys {
			err = store.Commit(CommitRequest{Key: key, Value: []byte("value"), Operation: "set", Author: DefaultAuthor()})
			require.NoError(t, err, "should allow key: %s", key)
		}
	})
}

func TestKeyToPath(t *testing.T) {
	tests := []struct {
		key  string
		path string
	}{
		{"key", "key.val"},
		{"app/config/db", "app/config/db.val"},
		{"deep/nested/path", "deep/nested/path.val"},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			assert.Equal(t, tt.path, keyToPath(tt.key))
		})
	}
}

func TestPathToKey(t *testing.T) {
	tests := []struct {
		path string
		key  string
	}{
		{"key.val", "key"},
		{"app/config/db.val", "app/config/db"},
		{"deep/nested/path.val", "deep/nested/path"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			assert.Equal(t, tt.key, pathToKey(tt.path))
		})
	}
}

func TestStore_CommitWithFormat(t *testing.T) {
	t.Run("includes format in commit message", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		err = store.Commit(CommitRequest{
			Key: "app/config", Value: []byte(`{"db": "postgres"}`), Operation: "set", Format: "json", Author: DefaultAuthor(),
		})
		require.NoError(t, err)

		// verify commit message contains format
		head, err := store.repo.Head()
		require.NoError(t, err)
		commit, err := store.repo.CommitObject(head.Hash())
		require.NoError(t, err)
		assert.Contains(t, commit.Message, "format: json")
	})

	t.Run("defaults to text format when empty", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		err = store.Commit(CommitRequest{Key: "key", Value: []byte("value"), Operation: "set", Author: DefaultAuthor()})
		require.NoError(t, err)

		head, err := store.repo.Head()
		require.NoError(t, err)
		commit, err := store.repo.CommitObject(head.Hash())
		require.NoError(t, err)
		assert.Contains(t, commit.Message, "format: text")
	})
}

func TestStore_ReadAllWithFormat(t *testing.T) {
	t.Run("returns format from commit metadata", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		// create keys with different formats
		require.NoError(t, store.Commit(CommitRequest{
			Key: "config/db", Value: []byte(`{"host":"localhost"}`), Operation: "set", Format: "json", Author: DefaultAuthor(),
		}))
		require.NoError(t, store.Commit(CommitRequest{
			Key: "config/app", Value: []byte("name: myapp"), Operation: "set", Format: "yaml", Author: DefaultAuthor(),
		}))
		require.NoError(t, store.Commit(CommitRequest{
			Key: "readme", Value: []byte("plain text"), Operation: "set", Format: "text", Author: DefaultAuthor(),
		}))

		result, err := store.ReadAll()
		require.NoError(t, err)
		require.Len(t, result, 3)

		assert.JSONEq(t, `{"host":"localhost"}`, string(result["config/db"].Value))
		assert.Equal(t, "json", result["config/db"].Format)

		assert.Equal(t, []byte("name: myapp"), result["config/app"].Value)
		assert.Equal(t, "yaml", result["config/app"].Format)

		assert.Equal(t, []byte("plain text"), result["readme"].Value)
		assert.Equal(t, "text", result["readme"].Format)
	})

	t.Run("defaults to text for old commits without format", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		// simulate old-style commit without format in message
		// by creating file and committing directly
		filePath := filepath.Join(store.cfg.Path, "old-key.val")
		require.NoError(t, os.WriteFile(filePath, []byte("old value"), 0o600))

		wt, err := store.repo.Worktree()
		require.NoError(t, err)
		_, err = wt.Add("old-key.val")
		require.NoError(t, err)
		_, err = wt.Commit("set old-key\n\nkey: old-key", &git.CommitOptions{
			Author: &object.Signature{Name: "test", Email: "test@test"},
		})
		require.NoError(t, err)

		result, err := store.ReadAll()
		require.NoError(t, err)
		require.Contains(t, result, "old-key")
		assert.Equal(t, "text", result["old-key"].Format, "should default to text for commits without format")
	})
}

func TestStore_BranchUsage(t *testing.T) {
	t.Run("commits go to configured branch for new repo", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history"), Branch: "develop"})
		require.NoError(t, err)

		// commit a key
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key1", Value: []byte("value1"),
			Operation: "set", Author: DefaultAuthor(),
		}))

		// verify HEAD is on the configured branch
		head, err := store.repo.Head()
		require.NoError(t, err)
		assert.Equal(t, "refs/heads/develop", head.Name().String(), "HEAD should be on develop branch")

		// verify commit is on the develop branch (not master)
		developRef, err := store.repo.Reference("refs/heads/develop", true)
		require.NoError(t, err)
		assert.Equal(t, head.Hash(), developRef.Hash(), "develop branch should have the latest commit")
	})

	t.Run("commits go to configured branch for existing repo", func(t *testing.T) {
		tmpDir := t.TempDir()
		repoPath := filepath.Join(tmpDir, ".history")

		// create repo on master first
		author := DefaultAuthor()
		store1, err := New(Config{Path: repoPath, Branch: "master"})
		require.NoError(t, err)
		require.NoError(t, store1.Commit(CommitRequest{
			Key: "key1", Value: []byte("value1"),
			Operation: "set", Author: author,
		}))

		// reopen with different branch
		store2, err := New(Config{Path: repoPath, Branch: "develop"})
		require.NoError(t, err)
		require.NoError(t, store2.Commit(CommitRequest{
			Key: "key2", Value: []byte("value2"),
			Operation: "set", Author: author,
		}))

		// verify HEAD is on develop
		head, err := store2.repo.Head()
		require.NoError(t, err)
		assert.Equal(t, "refs/heads/develop", head.Name().String(), "HEAD should be on develop branch")
	})
}

func TestStore_Head(t *testing.T) {
	t.Run("returns short commit hash", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		// make a commit
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key1", Value: []byte("value1"),
			Operation: "set", Author: DefaultAuthor(),
		}))

		hash, err := store.Head()
		require.NoError(t, err)
		assert.Len(t, hash, 7, "hash should be 7 characters (short form)")
		assert.Regexp(t, "^[0-9a-f]{7}$", hash, "hash should be hex characters")
	})

	t.Run("returns different hash after new commit", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		// initial commit
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key1", Value: []byte("value1"),
			Operation: "set", Author: DefaultAuthor(),
		}))
		hash1, err := store.Head()
		require.NoError(t, err)

		// second commit
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key2", Value: []byte("value2"),
			Operation: "set", Author: DefaultAuthor(),
		}))
		hash2, err := store.Head()
		require.NoError(t, err)

		assert.NotEqual(t, hash1, hash2, "hash should change after new commit")
	})
}

func TestParseFormatFromCommit(t *testing.T) {
	tests := []struct {
		name, message, expected string
	}{
		{"with format", "set key\n\nkey: test\nformat: json", "json"},
		{"text format", "set key\n\nkey: test\nformat: text", "text"},
		{"yaml format", "set key\n\nformat: yaml\nkey: test", "yaml"},
		{"no format in message", "set key\n\nkey: test", "text"},
		{"empty message", "", "text"},
		{"no metadata", "simple commit message", "text"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, parseFormatFromCommit(tc.message))
		})
	}
}

func TestParseOperationFromCommit(t *testing.T) {
	tests := []struct {
		name, message, expected string
	}{
		{"with operation", "set key\n\noperation: set\nkey: test", "set"},
		{"delete operation", "delete key\n\noperation: delete\nkey: test", "delete"},
		{"fallback to first word", "set key\n\nkey: test", "set"},
		{"delete fallback", "delete key\n\nkey: test", "delete"},
		{"empty message", "", "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, parseOperationFromCommit(tc.message))
		})
	}
}

func TestStore_History(t *testing.T) {
	t.Run("returns history for key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		author := DefaultAuthor()
		// create key with multiple updates
		require.NoError(t, store.Commit(CommitRequest{
			Key: "app/config", Value: []byte("v1"),
			Operation: "set", Format: "text", Author: author,
		}))
		require.NoError(t, store.Commit(CommitRequest{
			Key: "app/config", Value: []byte("v2"),
			Operation: "set", Format: "json", Author: author,
		}))
		require.NoError(t, store.Commit(CommitRequest{
			Key: "app/config", Value: []byte("v3"),
			Operation: "set", Format: "yaml", Author: author,
		}))

		history, err := store.History("app/config", 0)
		require.NoError(t, err)
		require.Len(t, history, 3)

		// newest first
		assert.Equal(t, []byte("v3"), history[0].Value)
		assert.Equal(t, "yaml", history[0].Format)
		assert.Equal(t, "set", history[0].Operation)
		assert.Equal(t, "stash", history[0].Author)
		assert.Len(t, history[0].Hash, 7)

		assert.Equal(t, []byte("v2"), history[1].Value)
		assert.Equal(t, "json", history[1].Format)

		assert.Equal(t, []byte("v1"), history[2].Value)
		assert.Equal(t, "text", history[2].Format)
	})

	t.Run("respects limit", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		author := DefaultAuthor()
		for i := range 10 {
			require.NoError(t, store.Commit(CommitRequest{
				Key: "key", Value: fmt.Appendf(nil, "v%d", i),
				Operation: "set", Author: author,
			}))
		}

		history, err := store.History("key", 3)
		require.NoError(t, err)
		assert.Len(t, history, 3)
	})

	t.Run("returns empty for nonexistent key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		history, err := store.History("nonexistent", 0)
		require.NoError(t, err)
		assert.Empty(t, history)
	})

	t.Run("rejects invalid key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		_, err = store.History("../etc/passwd", 0)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key")
	})
}

func TestStore_CommitTimestampConsistency(t *testing.T) {
	t.Run("commit message and author timestamp match", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		err = store.Commit(CommitRequest{
			Key: "test/key", Value: []byte("value"), Operation: "set", Format: "text", Author: DefaultAuthor(),
		})
		require.NoError(t, err)

		// get the commit and extract both timestamps
		head, err := store.repo.Head()
		require.NoError(t, err)
		commit, err := store.repo.CommitObject(head.Hash())
		require.NoError(t, err)

		// extract timestamp from commit message
		var msgTimestamp string
		for line := range strings.SplitSeq(commit.Message, "\n") {
			if ts, found := strings.CutPrefix(line, "timestamp: "); found {
				msgTimestamp = ts
				break
			}
		}
		require.NotEmpty(t, msgTimestamp, "commit message should contain timestamp")

		// parse both timestamps
		msgTime, err := time.Parse(time.RFC3339, msgTimestamp)
		require.NoError(t, err)

		authorTime := commit.Author.When

		// timestamps should be exactly equal (same time captured once)
		assert.True(t, authorTime.Equal(msgTime), "commit message timestamp (%v) and author timestamp (%v) should be identical",
			msgTime, authorTime)
	})
}

func TestStore_ConcurrentCommits(t *testing.T) {
	t.Run("concurrent commits are safe", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, storeErr := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, storeErr)

		const numGoroutines = 10
		done := make(chan error, numGoroutines)

		// run concurrent commits - this should not cause race conditions or panic
		for i := range numGoroutines {
			go func(idx int) {
				key := fmt.Sprintf("key%d", idx)
				value := fmt.Sprintf("value%d", idx)
				commitErr := store.Commit(CommitRequest{
					Key: key, Value: []byte(value), Operation: "set", Author: DefaultAuthor(),
				})
				done <- commitErr
			}(i)
		}

		// collect results and count successes
		var successCount int
		for range numGoroutines {
			if err := <-done; err == nil {
				successCount++
			}
		}
		assert.GreaterOrEqual(t, successCount, 1, "at least one commit should succeed")
		t.Logf("concurrent commits: %d/%d succeeded", successCount, numGoroutines)

		// verify results match success count
		result, readErr := store.ReadAll()
		require.NoError(t, readErr)
		assert.Len(t, result, successCount, "stored keys should match successful commits")
	})
}

func TestStore_GetRevision(t *testing.T) {
	t.Run("returns value at specific revision", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		author := DefaultAuthor()
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key", Value: []byte("v1"),
			Operation: "set", Format: "text", Author: author,
		}))

		// get hash of first commit
		head1, err := store.repo.Head()
		require.NoError(t, err)
		hash1 := head1.Hash().String()

		require.NoError(t, store.Commit(CommitRequest{
			Key: "key", Value: []byte("v2"),
			Operation: "set", Format: "json", Author: author,
		}))

		// get value at first revision
		value, format, err := store.GetRevision("key", hash1)
		require.NoError(t, err)
		assert.Equal(t, []byte("v1"), value)
		assert.Equal(t, "text", format)
	})

	t.Run("returns value at short hash", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		author := DefaultAuthor()
		require.NoError(t, store.Commit(CommitRequest{
			Key: "key", Value: []byte("v1"),
			Operation: "set", Format: "json", Author: author,
		}))

		head, err := store.repo.Head()
		require.NoError(t, err)
		shortHash := head.Hash().String()[:7]

		value, format, err := store.GetRevision("key", shortHash)
		require.NoError(t, err)
		assert.Equal(t, []byte("v1"), value)
		assert.Equal(t, "json", format)
	})

	t.Run("fails with invalid revision", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		_, _, err = store.GetRevision("key", "invalid-rev")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to resolve revision")
	})

	t.Run("fails for file not in revision", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		author := DefaultAuthor()
		require.NoError(t, store.Commit(CommitRequest{Key: "key1", Value: []byte("v1"), Operation: "set", Author: author}))

		head, err := store.repo.Head()
		require.NoError(t, err)
		hash := head.Hash().String()

		// key2 doesn't exist at this revision
		_, _, err = store.GetRevision("key2", hash)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "file not found")
	})

	t.Run("rejects invalid key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		_, _, err = store.GetRevision("../etc/passwd", "abc123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid key")
	})
}

// pins the finding that secret values reached the repository in plaintext
func TestStore_SecretsEncryption(t *testing.T) {
	newCrypto := func(t *testing.T, key string) *kvstore.Crypto {
		t.Helper()
		c, err := kvstore.NewCrypto([]byte(key))
		require.NoError(t, err)
		return c
	}
	author := DefaultAuthor()
	const secret = "app/secrets/db"

	t.Run("secret is stored encrypted and read back decrypted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".history")
		gs, err := New(Config{Path: path, Encryptor: newCrypto(t, "master-key-0123456789")})
		require.NoError(t, err)

		require.NoError(t, gs.Commit(CommitRequest{Key: secret, Value: []byte("hunter2"), Operation: "set", Format: "text", Author: author}))
		require.NoError(t, gs.Commit(CommitRequest{Key: "app/config", Value: []byte("$ENC$looks-like-envelope"), Operation: "set", Author: author}))

		raw, err := os.ReadFile(filepath.Join(path, "app", "secrets", "db.val"))
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(string(raw), encPrefix))
		assert.NotContains(t, string(raw), "hunter2")

		history, err := gs.History(secret, 0)
		require.NoError(t, err)
		require.Len(t, history, 1)
		assert.Equal(t, []byte("hunter2"), history[0].Value)

		value, _, err := gs.GetRevision(secret, history[0].Hash)
		require.NoError(t, err)
		assert.Equal(t, []byte("hunter2"), value)

		all, err := gs.ReadAll()
		require.NoError(t, err)
		assert.Equal(t, []byte("hunter2"), all[secret].Value)
		assert.Equal(t, []byte("$ENC$looks-like-envelope"), all["app/config"].Value)
	})

	t.Run("secret plaintext resembling the envelope is still encrypted", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".history")
		gs, err := New(Config{Path: path, Encryptor: newCrypto(t, "master-key-0123456789")})
		require.NoError(t, err)

		require.NoError(t, gs.Commit(CommitRequest{Key: secret, Value: []byte("$ENC$not-really"), Operation: "set", Author: author}))
		raw, err := os.ReadFile(filepath.Join(path, "app", "secrets", "db.val"))
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "not-really")

		all, err := gs.ReadAll()
		require.NoError(t, err)
		assert.Equal(t, []byte("$ENC$not-really"), all[secret].Value)
	})

	t.Run("zk value passes through unchanged", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".history")
		gs, err := New(Config{Path: path, Encryptor: newCrypto(t, "master-key-0123456789")})
		require.NoError(t, err)

		zk := []byte("$ZK$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==")
		require.NoError(t, gs.Commit(CommitRequest{Key: secret, Value: zk, Operation: "set", Author: author}))
		raw, err := os.ReadFile(filepath.Join(path, "app", "secrets", "db.val"))
		require.NoError(t, err)
		assert.Equal(t, zk, raw)
	})

	t.Run("legacy plaintext is returned as is", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".history")
		plain, err := New(Config{Path: path})
		require.NoError(t, err)
		require.NoError(t, plain.Commit(CommitRequest{Key: secret, Value: []byte("old-plain"), Operation: "set", Author: author}))

		gs, err := New(Config{Path: path, Encryptor: newCrypto(t, "master-key-0123456789")})
		require.NoError(t, err)
		history, err := gs.History(secret, 0)
		require.NoError(t, err)
		require.Len(t, history, 1)
		assert.Equal(t, []byte("old-plain"), history[0].Value)

		all, err := gs.ReadAll()
		require.NoError(t, err)
		assert.Equal(t, []byte("old-plain"), all[secret].Value)
	})

	t.Run("encrypted value without encryptor is an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".history")
		gs, err := New(Config{Path: path, Encryptor: newCrypto(t, "master-key-0123456789")})
		require.NoError(t, err)
		require.NoError(t, gs.Commit(CommitRequest{Key: secret, Value: []byte("hunter2"), Operation: "set", Author: author}))
		head, err := gs.Head()
		require.NoError(t, err)

		plain, err := New(Config{Path: path})
		require.NoError(t, err)

		_, err = plain.ReadAll()
		require.ErrorContains(t, err, "no secrets key is configured")
		_, err = plain.History(secret, 0)
		require.ErrorContains(t, err, "no secrets key is configured")
		_, _, err = plain.GetRevision(secret, head)
		require.ErrorContains(t, err, "no secrets key is configured")
	})

	t.Run("wrong key is an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".history")
		gs, err := New(Config{Path: path, Encryptor: newCrypto(t, "master-key-0123456789")})
		require.NoError(t, err)
		require.NoError(t, gs.Commit(CommitRequest{Key: secret, Value: []byte("hunter2"), Operation: "set", Author: author}))
		head, err := gs.Head()
		require.NoError(t, err)

		wrong, err := New(Config{Path: path, Encryptor: newCrypto(t, "another-key-0123456789")})
		require.NoError(t, err)

		_, err = wrong.ReadAll()
		require.ErrorContains(t, err, "failed to decrypt")
		_, err = wrong.History(secret, 0)
		require.ErrorContains(t, err, "failed to decrypt")
		_, _, err = wrong.GetRevision(secret, head)
		require.ErrorContains(t, err, "failed to decrypt")
	})

	t.Run("damaged payload is an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), ".history")
		gs, err := New(Config{Path: path, Encryptor: newCrypto(t, "master-key-0123456789")})
		require.NoError(t, err)
		require.NoError(t, gs.Commit(CommitRequest{Key: secret, Value: []byte("hunter2"), Operation: "set", Author: author}))

		require.NoError(t, os.WriteFile(filepath.Join(path, "app", "secrets", "db.val"), []byte(encPrefix+"not base64!"), 0o600))
		_, err = gs.ReadAll()
		require.ErrorContains(t, err, "failed to decrypt")
	})
}

func TestStore_History_BoundsConcurrentDecryption(t *testing.T) {
	var inFlight, peak atomic.Int32
	enc := &EncryptorMock{
		EncryptFunc: func(value []byte) ([]byte, error) { return value, nil },
		DecryptFunc: func(encrypted []byte) ([]byte, error) {
			n := inFlight.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
			inFlight.Add(-1)
			return encrypted, nil
		},
	}
	gs, err := New(Config{Path: filepath.Join(t.TempDir(), ".history"), Encryptor: enc})
	require.NoError(t, err)
	author := DefaultAuthor()
	for i := range 6 {
		require.NoError(t, gs.Commit(CommitRequest{Key: "app/secrets/db", Value: fmt.Appendf(nil, "v%d", i), Operation: "set", Author: author}))
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			history, histErr := gs.History("app/secrets/db", 0)
			if histErr != nil {
				t.Errorf("history: %v", histErr)
				return
			}
			assert.Len(t, history, 6)
		})
	}
	wg.Wait()

	assert.LessOrEqual(t, peak.Load(), int32(maxConcurrentDecrypt))
	assert.Greater(t, peak.Load(), int32(1))
}

// pins the finding that a poisoned checkout could point .val entries outside the repository
func TestStore_Symlinks(t *testing.T) {
	author := DefaultAuthor()

	t.Run("readall skips symlinked values", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, ".history")
		gs, err := New(Config{Path: path})
		require.NoError(t, err)
		require.NoError(t, gs.Commit(CommitRequest{Key: "real", Value: []byte("ok"), Operation: "set", Author: author}))

		outside := filepath.Join(tmpDir, "outside.txt")
		require.NoError(t, os.WriteFile(outside, []byte("host-credential"), 0o600))
		require.NoError(t, os.Symlink(outside, filepath.Join(path, "exfil.val")))

		all, err := gs.ReadAll()
		require.NoError(t, err)
		assert.Equal(t, []byte("ok"), all["real"].Value)
		assert.NotContains(t, all, "exfil")
	})

	t.Run("commit refuses a value symlinked outside the repository", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, ".history")
		gs, err := New(Config{Path: path})
		require.NoError(t, err)

		outside := filepath.Join(tmpDir, "outside.txt")
		require.NoError(t, os.WriteFile(outside, []byte("untouched"), 0o600))
		require.NoError(t, os.Symlink(outside, filepath.Join(path, "link.val")))

		err = gs.Commit(CommitRequest{Key: "link", Value: []byte("overwrite"), Operation: "set", Author: author})
		require.Error(t, err)
		content, err := os.ReadFile(outside)
		require.NoError(t, err)
		assert.Equal(t, "untouched", string(content))
	})

	t.Run("commit refuses a parent directory symlinked outside the repository", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, ".history")
		gs, err := New(Config{Path: path})
		require.NoError(t, err)

		outsideDir := filepath.Join(tmpDir, "outside")
		require.NoError(t, os.Mkdir(outsideDir, 0o750))
		require.NoError(t, os.Symlink(outsideDir, filepath.Join(path, "app")))

		err = gs.Commit(CommitRequest{Key: "app/config", Value: []byte("escaped"), Operation: "set", Author: author})
		require.Error(t, err)
		_, statErr := os.Stat(filepath.Join(outsideDir, "config.val"))
		assert.True(t, os.IsNotExist(statErr))
	})

	t.Run("delete unlinks a symlinked value without touching its target", func(t *testing.T) {
		tmpDir := t.TempDir()
		path := filepath.Join(tmpDir, ".history")
		gs, err := New(Config{Path: path})
		require.NoError(t, err)

		outside := filepath.Join(tmpDir, "outside.txt")
		require.NoError(t, os.WriteFile(outside, []byte("untouched"), 0o600))
		require.NoError(t, os.Symlink(outside, filepath.Join(path, "link.val")))

		require.ErrorContains(t, gs.Delete("link", author), "failed to stage deletion")
		content, err := os.ReadFile(outside)
		require.NoError(t, err)
		assert.Equal(t, "untouched", string(content))
		_, statErr := os.Lstat(filepath.Join(path, "link.val"))
		assert.True(t, os.IsNotExist(statErr))
	})
}
