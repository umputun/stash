package git_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/git/mocks"
)

func TestService_Record(t *testing.T) {
	author := git.Author{Name: "user", Email: "user@test"}
	setReq := git.CommitRequest{Key: "test-key", Value: []byte("v"), Operation: "update", Format: "text", Author: author}
	delReq := git.CommitRequest{Key: "test-key", Operation: "delete", Author: author}

	tests := []struct {
		name       string
		req        git.CommitRequest
		pushSync   bool
		writeErr   error
		commitErr  error
		pullErr    error
		pushErr    error
		wantCommit int
		wantDelete int
		wantPull   int
		wantPush   int
	}{
		{name: "commit no push", req: setReq, wantCommit: 1},
		{name: "commit with push", req: setReq, pushSync: true, wantCommit: 1, wantPull: 1, wantPush: 1},
		{name: "delete routes to store delete", req: delReq, wantDelete: 1},
		{name: "delete with push", req: delReq, pushSync: true, wantDelete: 1, wantPull: 1, wantPush: 1},
		{name: "write fails, nothing committed", req: setReq, pushSync: true, writeErr: errors.New("db error")},
		{name: "commit fails, write still succeeds", req: setReq, pushSync: true, commitErr: errors.New("commit error"), wantCommit: 1},
		{name: "pull fails, no push", req: setReq, pushSync: true, pullErr: errors.New("pull error"), wantCommit: 1, wantPull: 1},
		{name: "push fails, write still succeeds", req: setReq, pushSync: true, pushErr: errors.New("push error"), wantCommit: 1,
			wantPull: 1, wantPush: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &mocks.StorerMock{
				CommitFunc: func(req git.CommitRequest) error { return tc.commitErr },
				DeleteFunc: func(key string, author git.Author) error { return tc.commitErr },
				PullFunc:   func() error { return tc.pullErr },
				PushFunc:   func() error { return tc.pushErr },
			}

			s := git.NewService(st, tc.pushSync)
			err := s.Record(func() (git.CommitRequest, error) { return tc.req, tc.writeErr })
			if tc.writeErr != nil {
				require.ErrorIs(t, err, tc.writeErr)
			} else {
				require.NoError(t, err)
			}

			assert.Len(t, st.CommitCalls(), tc.wantCommit)
			assert.Len(t, st.DeleteCalls(), tc.wantDelete)
			assert.Len(t, st.PullCalls(), tc.wantPull)
			assert.Len(t, st.PushCalls(), tc.wantPush)
			if tc.wantCommit > 0 {
				assert.Equal(t, setReq, st.CommitCalls()[0].Req)
			}
			if tc.wantDelete > 0 {
				assert.Equal(t, "test-key", st.DeleteCalls()[0].Key)
				assert.Equal(t, author, st.DeleteCalls()[0].Author)
			}
		})
	}
}

func TestService_Record_OrdersWriteAndCommit(t *testing.T) {
	// db write and git commit ran under separate locks, so git could record writes out of db order
	var mu sync.Mutex
	var events []string
	add := func(e string) {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
	}

	release := make(chan struct{})
	st := &mocks.StorerMock{CommitFunc: func(req git.CommitRequest) error {
		if req.Key == "a" {
			<-release
		}
		add("commit " + req.Key)
		return nil
	}}
	s := git.NewService(st, false)

	aWrote, bWrote := make(chan struct{}), make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		assert.NoError(t, s.Record(func() (git.CommitRequest, error) {
			add("write a")
			close(aWrote)
			return git.CommitRequest{Key: "a", Operation: "update"}, nil
		}))
	}()
	<-aWrote
	go func() {
		defer wg.Done()
		assert.NoError(t, s.Record(func() (git.CommitRequest, error) {
			add("write b")
			close(bWrote)
			return git.CommitRequest{Key: "b", Operation: "update"}, nil
		}))
	}()

	select {
	case <-bWrote:
		t.Fatal("second write ran while the first commit was in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	wg.Wait()

	assert.Equal(t, []string{"write a", "commit a", "write b", "commit b"}, events)
}

func TestService_Record_PushOutsideLock(t *testing.T) {
	pushing, release := make(chan struct{}), make(chan struct{})
	var pushes atomic.Int32
	st := &mocks.StorerMock{
		CommitFunc: func(req git.CommitRequest) error { return nil },
		PullFunc:   func() error { return nil },
		PushFunc: func() error {
			if pushes.Add(1) == 1 {
				close(pushing)
				<-release
			}
			return nil
		},
	}
	s := git.NewService(st, true)

	done := make(chan struct{})
	go func() {
		defer close(done)
		assert.NoError(t, s.Record(func() (git.CommitRequest, error) { return git.CommitRequest{Key: "a", Operation: "update"}, nil }))
	}()
	<-pushing

	wrote := false
	require.NoError(t, s.Record(func() (git.CommitRequest, error) {
		wrote = true
		return git.CommitRequest{Key: "b", Operation: "update"}, nil
	}))
	assert.True(t, wrote)
	close(release)
	<-done
}

func TestNewService(t *testing.T) {
	st := &mocks.StorerMock{}
	s := git.NewService(st, true)
	assert.NotNil(t, s)
}

func TestService_History(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		entries := []git.HistoryEntry{{Hash: "abc123", Author: "admin", Operation: "set"}}
		st := &mocks.StorerMock{
			HistoryFunc: func(key string, limit int) ([]git.HistoryEntry, error) { return entries, nil },
		}
		s := git.NewService(st, false)
		result, err := s.History("test-key", 10)
		require.NoError(t, err)
		assert.Equal(t, entries, result)
		assert.Len(t, st.HistoryCalls(), 1)
		assert.Equal(t, "test-key", st.HistoryCalls()[0].Key)
		assert.Equal(t, 10, st.HistoryCalls()[0].Limit)
	})

	t.Run("error propagation", func(t *testing.T) {
		st := &mocks.StorerMock{
			HistoryFunc: func(key string, limit int) ([]git.HistoryEntry, error) {
				return nil, errors.New("history error")
			},
		}
		s := git.NewService(st, false)
		_, err := s.History("test-key", 10)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "history:")
		assert.Contains(t, err.Error(), "history error")
	})
}

func TestService_GetRevision(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		st := &mocks.StorerMock{
			GetRevisionFunc: func(key, rev string) ([]byte, string, error) {
				return []byte("value"), "json", nil
			},
		}
		s := git.NewService(st, false)
		value, format, err := s.GetRevision("test-key", "abc123")
		require.NoError(t, err)
		assert.Equal(t, []byte("value"), value)
		assert.Equal(t, "json", format)
		assert.Len(t, st.GetRevisionCalls(), 1)
		assert.Equal(t, "test-key", st.GetRevisionCalls()[0].Key)
		assert.Equal(t, "abc123", st.GetRevisionCalls()[0].Rev)
	})

	t.Run("error propagation", func(t *testing.T) {
		st := &mocks.StorerMock{
			GetRevisionFunc: func(key, rev string) ([]byte, string, error) {
				return nil, "", errors.New("revision error")
			},
		}
		s := git.NewService(st, false)
		_, _, err := s.GetRevision("test-key", "abc123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get revision:")
		assert.Contains(t, err.Error(), "revision error")
	})
}
