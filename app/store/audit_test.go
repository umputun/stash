package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/umputun/stash/app/enum"
)

func TestStore_AuditLog(t *testing.T) {
	ctx := context.Background()

	t.Run("log and query", func(t *testing.T) {
		st, err := New(":memory:")
		require.NoError(t, err)
		defer st.Close()

		// log some entries
		now := time.Now()
		entries := []AuditEntry{
			{Timestamp: now.Add(-2 * time.Hour), Action: enum.AuditActionRead, Key: "app/config", Actor: "admin", ActorType: enum.ActorTypeUser, Result: enum.AuditResultSuccess, IP: "192.168.1.1", UserAgent: "test/1.0"},
			{Timestamp: now.Add(-1 * time.Hour), Action: enum.AuditActionUpdate, Key: "app/config", Actor: "admin", ActorType: enum.ActorTypeUser, Result: enum.AuditResultSuccess, ValueSize: intPtr(100)},
			{Timestamp: now, Action: enum.AuditActionRead, Key: "db/password", Actor: "token:abcd", ActorType: enum.ActorTypeToken, Result: enum.AuditResultDenied},
		}

		for _, e := range entries {
			require.NoError(t, st.LogAudit(ctx, e))
		}

		// query all
		results, total, err := st.QueryAudit(ctx, AuditQuery{})
		require.NoError(t, err)
		assert.Equal(t, 3, total)
		assert.Len(t, results, 3)
		assert.Equal(t, "db/password", results[0].Key, "newest first")

		// query by key prefix
		results, total, err = st.QueryAudit(ctx, AuditQuery{Key: "app/*"})
		require.NoError(t, err)
		assert.Equal(t, 2, total)
		assert.Len(t, results, 2)

		// query by actor
		_, total, err = st.QueryAudit(ctx, AuditQuery{Actor: "admin"})
		require.NoError(t, err)
		assert.Equal(t, 2, total)

		// query by action
		_, total, err = st.QueryAudit(ctx, AuditQuery{Action: enum.AuditActionRead})
		require.NoError(t, err)
		assert.Equal(t, 2, total)

		// query by result
		_, total, err = st.QueryAudit(ctx, AuditQuery{Result: enum.AuditResultDenied})
		require.NoError(t, err)
		assert.Equal(t, 1, total)

		// query with limit
		results, _, err = st.QueryAudit(ctx, AuditQuery{Limit: 1})
		require.NoError(t, err)
		assert.Len(t, results, 1)
	})

	t.Run("delete older than", func(t *testing.T) {
		st, err := New(":memory:")
		require.NoError(t, err)
		defer st.Close()

		now := time.Now()
		entries := []AuditEntry{
			{Timestamp: now.Add(-48 * time.Hour), Action: enum.AuditActionRead, Key: "old", Actor: "user", ActorType: enum.ActorTypeUser, Result: enum.AuditResultSuccess},
			{Timestamp: now.Add(-24 * time.Hour), Action: enum.AuditActionRead, Key: "recent", Actor: "user", ActorType: enum.ActorTypeUser, Result: enum.AuditResultSuccess},
			{Timestamp: now, Action: enum.AuditActionRead, Key: "new", Actor: "user", ActorType: enum.ActorTypeUser, Result: enum.AuditResultSuccess},
		}

		for _, e := range entries {
			require.NoError(t, st.LogAudit(ctx, e))
		}

		// delete entries older than 36 hours
		deleted, err := st.DeleteAuditOlderThan(ctx, now.Add(-36*time.Hour))
		require.NoError(t, err)
		assert.Equal(t, int64(1), deleted)

		// verify only 2 entries remain
		results, total, err := st.QueryAudit(ctx, AuditQuery{})
		require.NoError(t, err)
		assert.Equal(t, 2, total)
		assert.Len(t, results, 2)
	})

	t.Run("time range filter", func(t *testing.T) {
		st, err := New(":memory:")
		require.NoError(t, err)
		defer st.Close()

		now := time.Now()
		entries := []AuditEntry{
			{Timestamp: now.Add(-48 * time.Hour), Action: enum.AuditActionRead, Key: "a", Actor: "u", ActorType: enum.ActorTypeUser, Result: enum.AuditResultSuccess},
			{Timestamp: now.Add(-24 * time.Hour), Action: enum.AuditActionRead, Key: "b", Actor: "u", ActorType: enum.ActorTypeUser, Result: enum.AuditResultSuccess},
			{Timestamp: now, Action: enum.AuditActionRead, Key: "c", Actor: "u", ActorType: enum.ActorTypeUser, Result: enum.AuditResultSuccess},
		}

		for _, e := range entries {
			require.NoError(t, st.LogAudit(ctx, e))
		}

		// query with time range
		results, total, err := st.QueryAudit(ctx, AuditQuery{
			From: now.Add(-30 * time.Hour),
			To:   now.Add(-20 * time.Hour),
		})
		require.NoError(t, err)
		assert.Equal(t, 1, total)
		assert.Len(t, results, 1)
		assert.Equal(t, "b", results[0].Key)
	})
}

func intPtr(i int) *int {
	return &i
}
