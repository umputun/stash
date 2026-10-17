package git_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-pkgz/lgr"
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

			s := git.NewService(st, git.ServiceOpts{PushSync: tc.pushSync})
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
	s := git.NewService(st, git.ServiceOpts{})

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
	s := git.NewService(st, git.ServiceOpts{PushSync: true})

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
	s := git.NewService(st, git.ServiceOpts{PushSync: true})
	assert.NotNil(t, s)
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n, err := b.buf.Write(p)
	if err != nil {
		return n, fmt.Errorf("write: %w", err)
	}
	return n, nil
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestService_Run(t *testing.T) {
	startRun := func(t *testing.T, s *git.Service) (cancel func(), done chan struct{}) {
		t.Helper()
		ctx, cancelCtx := context.WithCancel(t.Context())
		done = make(chan struct{})
		go func() {
			defer close(done)
			s.Run(ctx)
		}()
		return cancelCtx, done
	}
	commitReq := func() (git.CommitRequest, error) { return git.CommitRequest{Key: "k", Operation: "update"}, nil }

	t.Run("zero interval returns at once", func(t *testing.T) {
		st := &mocks.StorerMock{}
		git.NewService(st, git.ServiceOpts{}).Run(t.Context())
		assert.Empty(t, st.PushContextCalls())
	})

	t.Run("initial push at start with a bounded context, no final push when nothing is pending", func(t *testing.T) {
		st := &mocks.StorerMock{PushContextFunc: func(ctx context.Context) error {
			deadline, ok := ctx.Deadline()
			assert.True(t, ok)
			assert.LessOrEqual(t, time.Until(deadline), 10*time.Second)
			return nil
		}}
		s := git.NewService(st, git.ServiceOpts{PushInterval: time.Hour})
		cancel, done := startRun(t, s)
		require.Eventually(t, func() bool { return len(st.PushContextCalls()) == 1 }, time.Second, 5*time.Millisecond)
		cancel()
		<-done
		assert.Len(t, st.PushContextCalls(), 1)
	})

	t.Run("failed startup push is retried on a tick with no writes, idle ticks do not push", func(t *testing.T) {
		var calls atomic.Int32
		st := &mocks.StorerMock{PushContextFunc: func(context.Context) error {
			if calls.Add(1) == 1 {
				return errors.New("remote unreachable")
			}
			return nil
		}}
		s := git.NewService(st, git.ServiceOpts{PushInterval: 20 * time.Millisecond})
		cancel, done := startRun(t, s)
		defer func() { cancel(); <-done }()

		require.Eventually(t, func() bool { return calls.Load() == 2 }, time.Second, 5*time.Millisecond)
		time.Sleep(100 * time.Millisecond)
		assert.Equal(t, int32(2), calls.Load())
	})

	t.Run("commit triggers a push without inline pull", func(t *testing.T) {
		st := &mocks.StorerMock{
			CommitFunc:      func(req git.CommitRequest) error { return nil },
			PushContextFunc: func(context.Context) error { return nil },
		}
		s := git.NewService(st, git.ServiceOpts{PushSync: true, PushInterval: time.Hour})
		cancel, done := startRun(t, s)
		defer func() { cancel(); <-done }()
		require.Eventually(t, func() bool { return len(st.PushContextCalls()) == 1 }, time.Second, 5*time.Millisecond)

		require.NoError(t, s.Record(commitReq))
		require.Eventually(t, func() bool { return len(st.PushContextCalls()) == 2 }, time.Second, 5*time.Millisecond)
		assert.Empty(t, st.PullCalls())
		assert.Empty(t, st.PushCalls())
	})

	t.Run("rejected push is logged as an error and retried, never forced", func(t *testing.T) {
		buf := &syncBuffer{}
		lgr.Setup(lgr.Out(buf), lgr.Err(buf))
		t.Cleanup(func() { lgr.Setup(lgr.Out(os.Stdout), lgr.Err(os.Stderr)) })

		var calls atomic.Int32
		st := &mocks.StorerMock{PushContextFunc: func(context.Context) error {
			calls.Add(1)
			return fmt.Errorf("failed to push: %w", errors.New("non-fast-forward update: refs/heads/master"))
		}}
		s := git.NewService(st, git.ServiceOpts{PushInterval: 20 * time.Millisecond})
		cancel, done := startRun(t, s)
		require.Eventually(t, func() bool { return calls.Load() >= 2 }, time.Second, 5*time.Millisecond)
		cancel()
		<-done
		assert.Contains(t, buf.String(), "ERROR")
		assert.Contains(t, buf.String(), "remote branch moved")
	})

	t.Run("cancel makes one final push and run returns after it", func(t *testing.T) {
		var calls atomic.Int32
		finalStarted, release := make(chan struct{}), make(chan struct{})
		st := &mocks.StorerMock{
			CommitFunc: func(req git.CommitRequest) error { return nil },
			PushContextFunc: func(ctx context.Context) error {
				switch calls.Add(1) {
				case 1:
					return nil
				case 2:
					return errors.New("remote unreachable")
				default:
					close(finalStarted)
					<-release
					_, ok := ctx.Deadline()
					assert.True(t, ok)
					return nil
				}
			},
		}
		s := git.NewService(st, git.ServiceOpts{PushInterval: time.Hour})
		cancel, done := startRun(t, s)
		require.Eventually(t, func() bool { return calls.Load() == 1 }, time.Second, 5*time.Millisecond)
		require.NoError(t, s.Record(commitReq))
		require.Eventually(t, func() bool { return calls.Load() == 2 }, time.Second, 5*time.Millisecond)

		cancel()
		<-finalStarted
		select {
		case <-done:
			t.Fatal("run returned before the final push finished")
		case <-time.After(100 * time.Millisecond):
		}
		close(release)
		<-done
		assert.Equal(t, int32(3), calls.Load())
	})
}

func TestService_History(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		entries := []git.HistoryEntry{{Hash: "abc123", Author: "admin", Operation: "set"}}
		st := &mocks.StorerMock{
			HistoryFunc: func(key string, limit int) ([]git.HistoryEntry, error) { return entries, nil },
		}
		s := git.NewService(st, git.ServiceOpts{})
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
		s := git.NewService(st, git.ServiceOpts{})
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
		s := git.NewService(st, git.ServiceOpts{})
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
		s := git.NewService(st, git.ServiceOpts{})
		_, _, err := s.GetRevision("test-key", "abc123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get revision:")
		assert.Contains(t, err.Error(), "revision error")
	})
}
