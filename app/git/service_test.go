package git_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/git"
	"github.com/umputun/stash/app/git/mocks"
)

func TestService_Commit(t *testing.T) {
	tests := []struct {
		name      string
		pushSync  bool
		commitErr error
		pullErr   error
		pushErr   error
		wantErr   bool
	}{
		{name: "commit success no push", pushSync: false},
		{name: "commit success with push", pushSync: true},
		{name: "commit fails", commitErr: errors.New("commit error"), wantErr: true},
		{name: "pull fails", pushSync: true, pullErr: errors.New("pull error"), wantErr: true},
		{name: "push fails", pushSync: true, pushErr: errors.New("push error"), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &mocks.StorerMock{
				CommitFunc: func(req git.CommitRequest) error { return tc.commitErr },
				PullFunc:   func() error { return tc.pullErr },
				PushFunc:   func() error { return tc.pushErr },
			}

			s := git.NewService(st, tc.pushSync)
			req := git.CommitRequest{Key: "test-key", Value: []byte("test-value"), Operation: "set", Format: "text", Author: git.Author{Name: "user", Email: "user@test"}}
			err := s.Commit(req)

			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			// verify commit was called
			assert.Len(t, st.CommitCalls(), 1)
			assert.Equal(t, "test-key", st.CommitCalls()[0].Req.Key)

			// verify pull/push based on pushSync and errors
			switch {
			case tc.commitErr != nil:
				assert.Empty(t, st.PullCalls())
				assert.Empty(t, st.PushCalls())
			case tc.pushSync:
				assert.Len(t, st.PullCalls(), 1)
				if tc.pullErr == nil {
					assert.Len(t, st.PushCalls(), 1)
				} else {
					assert.Empty(t, st.PushCalls())
				}
			default:
				assert.Empty(t, st.PullCalls())
				assert.Empty(t, st.PushCalls())
			}
		})
	}
}

func TestService_Delete(t *testing.T) {
	tests := []struct {
		name      string
		pushSync  bool
		deleteErr error
		pullErr   error
		pushErr   error
		wantErr   bool
	}{
		{name: "delete success no push", pushSync: false},
		{name: "delete success with push", pushSync: true},
		{name: "delete fails", deleteErr: errors.New("delete error"), wantErr: true},
		{name: "pull fails after delete", pushSync: true, pullErr: errors.New("pull error"), wantErr: true},
		{name: "push fails after delete", pushSync: true, pushErr: errors.New("push error"), wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			st := &mocks.StorerMock{
				DeleteFunc: func(key string, author git.Author) error { return tc.deleteErr },
				PullFunc:   func() error { return tc.pullErr },
				PushFunc:   func() error { return tc.pushErr },
			}

			s := git.NewService(st, tc.pushSync)
			err := s.Delete("test-key", git.Author{Name: "user", Email: "user@test"})

			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			// verify delete was called
			assert.Len(t, st.DeleteCalls(), 1)
			assert.Equal(t, "test-key", st.DeleteCalls()[0].Key)
			assert.Equal(t, "user", st.DeleteCalls()[0].Author.Name)

			// verify pull/push based on pushSync and errors
			switch {
			case tc.deleteErr != nil:
				assert.Empty(t, st.PullCalls())
				assert.Empty(t, st.PushCalls())
			case tc.pushSync:
				assert.Len(t, st.PullCalls(), 1)
				if tc.pullErr == nil {
					assert.Len(t, st.PushCalls(), 1)
				} else {
					assert.Empty(t, st.PushCalls())
				}
			default:
				assert.Empty(t, st.PullCalls())
				assert.Empty(t, st.PushCalls())
			}
		})
	}
}

func TestNewService(t *testing.T) {
	st := &mocks.StorerMock{}
	s := git.NewService(st, true)
	assert.NotNil(t, s)
}
