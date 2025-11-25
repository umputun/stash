package git

import (
	"os"
	"path/filepath"
	"testing"

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

		err = store.Commit("app/config/db", []byte("postgres://localhost/db"), "set", DefaultAuthor())
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

		err = store.Commit("deep/nested/path/key", []byte("value"), "set", DefaultAuthor())
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
		err = store.Commit("binary/key", binary, "set", DefaultAuthor())
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
		err = store.Commit("app/config/db", []byte("value"), "set", DefaultAuthor())
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
		require.NoError(t, store.Commit("key1", []byte("value1"), "set", DefaultAuthor()))
		require.NoError(t, store.Commit("app/config/db", []byte("postgres://"), "set", DefaultAuthor()))
		require.NoError(t, store.Commit("app/config/redis", []byte("redis://"), "set", DefaultAuthor()))

		// read all
		result, err := store.ReadAll()
		require.NoError(t, err)
		assert.Len(t, result, 3)
		assert.Equal(t, []byte("value1"), result["key1"])
		assert.Equal(t, []byte("postgres://"), result["app/config/db"])
		assert.Equal(t, []byte("redis://"), result["app/config/redis"])
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
		require.NoError(t, store.Commit("key1", []byte("value1"), "set", DefaultAuthor()))

		// get commit hash
		head, err := store.repo.Head()
		require.NoError(t, err)
		commitHash := head.Hash().String()

		// create second key
		require.NoError(t, store.Commit("key2", []byte("value2"), "set", DefaultAuthor()))

		// checkout first commit
		err = store.Checkout(commitHash)
		require.NoError(t, err)

		// verify only key1 exists
		result, err := store.ReadAll()
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, []byte("value1"), result["key1"])
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
}

func TestStore_Pull(t *testing.T) {
	t.Run("no-op without remote", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history")})
		require.NoError(t, err)

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
			err = store.Commit(key, []byte("malicious"), "set", DefaultAuthor())
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
			err = store.Commit(key, []byte("value"), "set", DefaultAuthor())
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

func TestStore_BranchUsage(t *testing.T) {
	t.Run("commits go to configured branch for new repo", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := New(Config{Path: filepath.Join(tmpDir, ".history"), Branch: "develop"})
		require.NoError(t, err)

		// commit a key
		require.NoError(t, store.Commit("key1", []byte("value1"), "set", DefaultAuthor()))

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
		require.NoError(t, store1.Commit("key1", []byte("value1"), "set", DefaultAuthor()))

		// reopen with different branch
		store2, err := New(Config{Path: repoPath, Branch: "develop"})
		require.NoError(t, err)
		require.NoError(t, store2.Commit("key2", []byte("value2"), "set", DefaultAuthor()))

		// verify HEAD is on develop
		head, err := store2.repo.Head()
		require.NoError(t, err)
		assert.Equal(t, "refs/heads/develop", head.Name().String(), "HEAD should be on develop branch")
	})
}
