package main

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/store"
)

func TestServerCmd_Execute(t *testing.T) {
	tmpDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())

	cmd := &ServerCmd{
		DB:    filepath.Join(tmpDir, "test.db"),
		Debug: false,
		ctx:   ctx,
	}
	cmd.Server.Address = "127.0.0.1:18490"
	cmd.Server.ReadTimeout = 5 * time.Second

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute(nil)
	}()

	// wait for server to start
	waitForServer(t, "http://127.0.0.1:18490/ping")

	// verify server is running
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:18490/ping")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// shutdown
	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestServerCmd_Execute_WithGitEnabled(t *testing.T) {
	tmpDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())

	cmd := &ServerCmd{
		DB:    filepath.Join(tmpDir, "test.db"),
		Debug: true,
		ctx:   ctx,
	}
	cmd.Server.Address = "127.0.0.1:18491"
	cmd.Server.ReadTimeout = 5 * time.Second
	cmd.Git.Enabled = true
	cmd.Git.Path = filepath.Join(tmpDir, ".history")
	cmd.Git.Branch = "master"

	errCh := make(chan error, 1)
	go func() {
		errCh <- cmd.Execute(nil)
	}()

	// wait for server to start
	waitForServer(t, "http://127.0.0.1:18491/ping")

	// shutdown
	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestRestoreCmd_Execute(t *testing.T) {
	tmpDir := t.TempDir()
	gitPath := filepath.Join(tmpDir, ".history")
	dbPath := filepath.Join(tmpDir, "test.db")

	// create git store and add some test data
	gitStore, err := git.New(git.Config{Path: gitPath, Branch: "master"})
	require.NoError(t, err)

	// commit test keys
	require.NoError(t, gitStore.Commit("app/key1", []byte("value1"), "set"))
	require.NoError(t, gitStore.Commit("app/key2", []byte("value2"), "set"))
	require.NoError(t, gitStore.Commit("config/db", []byte("postgres://localhost"), "set"))

	// get current HEAD commit hash
	headRef, err := gitStore.Head()
	require.NoError(t, err)

	// run restore command
	cmd := &RestoreCmd{Rev: headRef}
	cmd.DB = dbPath
	cmd.Git.Path = gitPath
	cmd.Git.Branch = "master"

	err = cmd.Execute(nil)
	require.NoError(t, err)

	// verify keys were restored to database
	kvStore, err := store.New(dbPath)
	require.NoError(t, err)
	defer kvStore.Close()

	val1, err := kvStore.Get("app/key1")
	require.NoError(t, err)
	assert.Equal(t, "value1", string(val1))

	val2, err := kvStore.Get("app/key2")
	require.NoError(t, err)
	assert.Equal(t, "value2", string(val2))

	val3, err := kvStore.Get("config/db")
	require.NoError(t, err)
	assert.Equal(t, "postgres://localhost", string(val3))
}

func TestRestoreCmd_Execute_InvalidRevision(t *testing.T) {
	tmpDir := t.TempDir()
	gitPath := filepath.Join(tmpDir, ".history")

	// create git store (empty)
	_, err := git.New(git.Config{Path: gitPath, Branch: "master"})
	require.NoError(t, err)

	cmd := &RestoreCmd{Rev: "abc123"}
	cmd.DB = filepath.Join(tmpDir, "test.db")
	cmd.Git.Path = gitPath
	cmd.Git.Branch = "master"

	err = cmd.Execute(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to checkout revision")
}
