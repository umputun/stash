package git

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

		err = store.Commit(CommitRequest{Key: "app/config/db", Value: []byte("postgres://localhost/db"), Operation: "set", Author: DefaultAuthor()})
		require.NoError(t, err)

		// verify file exists
		valFile := filepath.Join(store.cfg.Path, "app", "config", "db.val")
		content, err := os.ReadFile(valFile) //nolint:gosec // test code
		require.NoError(t, err)
		assert.Equal(t, "postgres://localhost/db", string(content))
	})

	t.Run("commits nested key", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		err = store.Commit(CommitRequest{Key: "deep/nested/path/key", Value: []byte("value"), Operation: "set", Author: DefaultAuthor()})
		require.NoError(t, err)

		valFile := filepath.Join(store.cfg.Path, "deep", "nested", "path", "key.val")
		content, err := os.ReadFile(valFile) //nolint:gosec // test code
		require.NoError(t, err)
		assert.Equal(t, "value", string(content))
	})

	t.Run("commits binary data", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

		binary := []byte{0x00, 0x01, 0xFF, 0xFE}
		err = store.Commit(CommitRequest{Key: "binary/key", Value: binary, Operation: "set", Author: DefaultAuthor()})
		require.NoError(t, err)

		valFile := filepath.Join(store.cfg.Path, "binary", "key.val")
		content, err := os.ReadFile(valFile) //nolint:gosec // test code
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
		err = store.Commit(CommitRequest{Key: "app/config/db", Value: []byte("value"), Operation: "set", Author: DefaultAuthor()})
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
		require.NoError(t, store.Commit(CommitRequest{Key: "key1", Value: []byte("value1"), Operation: "set", Author: DefaultAuthor()}))
		require.NoError(t, store.Commit(CommitRequest{Key: "app/config/db", Value: []byte("postgres://"), Operation: "set", Author: DefaultAuthor()}))
		require.NoError(t, store.Commit(CommitRequest{Key: "app/config/redis", Value: []byte("redis://"), Operation: "set", Author: DefaultAuthor()}))

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
		require.NoError(t, store.Commit(CommitRequest{Key: "key1", Value: []byte("value1"), Operation: "set", Author: DefaultAuthor()}))

		// get commit hash
		head, err := store.repo.Head()
		require.NoError(t, err)
		commitHash := head.Hash().String()

		// create second key
		require.NoError(t, store.Commit(CommitRequest{Key: "key2", Value: []byte("value2"), Operation: "set", Author: DefaultAuthor()}))

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
		require.NoError(t, store.Commit(CommitRequest{Key: "key1", Value: []byte("value1"), Operation: "set", Author: DefaultAuthor()}))

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
		store1, err := New(Config{Path: repoPath, Branch: "master"})
		require.NoError(t, err)
		require.NoError(t, store1.Commit(CommitRequest{Key: "key1", Value: []byte("value1"), Operation: "set", Author: DefaultAuthor()}))

		// reopen with different branch
		store2, err := New(Config{Path: repoPath, Branch: "develop"})
		require.NoError(t, err)
		require.NoError(t, store2.Commit(CommitRequest{Key: "key2", Value: []byte("value2"), Operation: "set", Author: DefaultAuthor()}))

		// verify HEAD is on develop
		head, err := store2.repo.Head()
		require.NoError(t, err)
		assert.Equal(t, "refs/heads/develop", head.Name().String(), "HEAD should be on develop branch")
	})
}
