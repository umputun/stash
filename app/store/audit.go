package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	log "github.com/go-pkgz/lgr"

	"github.com/umputun/stash/app/enum"
)

// AuditEntry represents a single audit log entry.
type AuditEntry struct {
	ID        int64            `json:"id" db:"id"`
	Timestamp time.Time        `json:"timestamp" db:"timestamp"`
	Action    enum.AuditAction `json:"action" db:"action"`
	Key       string           `json:"key" db:"key"`
	Actor     string           `json:"actor" db:"actor"`
	ActorType enum.ActorType   `json:"actor_type" db:"actor_type"`
	Result    enum.AuditResult `json:"result" db:"result"`
	IP        string           `json:"ip,omitempty" db:"ip"`
	UserAgent string           `json:"user_agent,omitempty" db:"user_agent"`
	ValueSize *int             `json:"value_size,omitempty" db:"value_size"`
	RequestID string           `json:"request_id,omitempty" db:"request_id"`
}

// AuditQuery defines filters for querying audit logs.
type AuditQuery struct {
	Key       string           // prefix match with * suffix, e.g., "app/*"
	Actor     string           // exact match
	ActorType enum.ActorType   // exact match (zero value = any)
	Action    enum.AuditAction // exact match (zero value = any)
	Result    enum.AuditResult // exact match (zero value = any)
	From      time.Time        // inclusive
	To        time.Time        // inclusive
	Limit     int              // max entries to return
}

// LogAudit inserts an audit entry into the audit_log table.
func (s *Store) LogAudit(ctx context.Context, entry AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := s.adoptQuery(`
		INSERT INTO audit_log (timestamp, action, key, actor, actor_type, result, ip, user_agent, value_size, request_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)

	_, err := s.db.ExecContext(ctx, query,
		entry.Timestamp.Format(time.RFC3339),
		entry.Action.String(),
		entry.Key,
		entry.Actor,
		entry.ActorType.String(),
		entry.Result.String(),
		entry.IP,
		entry.UserAgent,
		entry.ValueSize,
		entry.RequestID,
	)
	if err != nil {
		return fmt.Errorf("failed to insert audit entry: %w", err)
	}
	return nil
}

// QueryAudit retrieves audit entries matching the given filters.
// Returns entries ordered by timestamp descending (newest first).
func (s *Store) QueryAudit(ctx context.Context, q AuditQuery) ([]AuditEntry, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// build WHERE clause dynamically
	var conditions []string
	var args []any

	if q.Key != "" {
		if prefix, found := strings.CutSuffix(q.Key, "*"); found {
			conditions = append(conditions, "key LIKE ?")
			args = append(args, prefix+"%")
		} else {
			conditions = append(conditions, "key = ?")
			args = append(args, q.Key)
		}
	}

	if q.Actor != "" {
		conditions = append(conditions, "actor = ?")
		args = append(args, q.Actor)
	}

	if q.ActorType.String() != "" && q.ActorType != (enum.ActorType{}) {
		conditions = append(conditions, "actor_type = ?")
		args = append(args, q.ActorType.String())
	}

	if q.Action.String() != "" && q.Action != (enum.AuditAction{}) {
		conditions = append(conditions, "action = ?")
		args = append(args, q.Action.String())
	}

	if q.Result.String() != "" && q.Result != (enum.AuditResult{}) {
		conditions = append(conditions, "result = ?")
		args = append(args, q.Result.String())
	}

	if !q.From.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, q.From.Format(time.RFC3339))
	}

	if !q.To.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, q.To.Format(time.RFC3339))
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = " WHERE " + strings.Join(conditions, " AND ")
	}

	// get total count first
	countQuery := s.adoptQuery("SELECT COUNT(*) FROM audit_log" + whereClause)
	var total int
	if err := s.db.GetContext(ctx, &total, countQuery, args...); err != nil {
		return nil, 0, fmt.Errorf("failed to count audit entries: %w", err)
	}

	// get entries with limit
	limit := q.Limit
	if limit <= 0 {
		limit = 10000 // default limit
	}

	selectQuery := s.adoptQuery("SELECT id, timestamp, action, key, actor, actor_type, result, ip, user_agent, value_size, request_id FROM audit_log" + whereClause + " ORDER BY timestamp DESC LIMIT ?")
	args = append(args, limit)

	rows, err := s.db.QueryxContext(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query audit entries: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e auditRow
		if err := rows.StructScan(&e); err != nil {
			return nil, 0, fmt.Errorf("failed to scan audit entry: %w", err)
		}
		entries = append(entries, e.toAuditEntry())
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating audit rows: %w", err)
	}

	return entries, total, nil
}

// auditRow is used for scanning audit log rows from the database.
type auditRow struct {
	ID        int64   `db:"id"`
	Timestamp string  `db:"timestamp"`
	Action    string  `db:"action"`
	Key       string  `db:"key"`
	Actor     string  `db:"actor"`
	ActorType string  `db:"actor_type"`
	Result    string  `db:"result"`
	IP        *string `db:"ip"`
	UserAgent *string `db:"user_agent"`
	ValueSize *int    `db:"value_size"`
	RequestID *string `db:"request_id"`
}

// toAuditEntry converts the database row to an AuditEntry.
func (r auditRow) toAuditEntry() AuditEntry {
	ts, err := time.Parse(time.RFC3339, r.Timestamp)
	if err != nil {
		log.Printf("[WARN] failed to parse audit timestamp %q: %v", r.Timestamp, err)
	}
	action, err := enum.ParseAuditAction(r.Action)
	if err != nil {
		log.Printf("[WARN] failed to parse audit action %q: %v", r.Action, err)
	}
	actorType, err := enum.ParseActorType(r.ActorType)
	if err != nil {
		log.Printf("[WARN] failed to parse audit actor_type %q: %v", r.ActorType, err)
	}
	result, err := enum.ParseAuditResult(r.Result)
	if err != nil {
		log.Printf("[WARN] failed to parse audit result %q: %v", r.Result, err)
	}

	e := AuditEntry{
		ID:        r.ID,
		Timestamp: ts,
		Action:    action,
		Key:       r.Key,
		Actor:     r.Actor,
		ActorType: actorType,
		Result:    result,
		ValueSize: r.ValueSize,
	}

	if r.IP != nil {
		e.IP = *r.IP
	}
	if r.UserAgent != nil {
		e.UserAgent = *r.UserAgent
	}
	if r.RequestID != nil {
		e.RequestID = *r.RequestID
	}

	return e
}

// DeleteAuditOlderThan removes audit entries older than the given time.
// Returns the number of deleted entries.
func (s *Store) DeleteAuditOlderThan(ctx context.Context, olderThan time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := s.adoptQuery("DELETE FROM audit_log WHERE timestamp < ?")
	result, err := s.db.ExecContext(ctx, query, olderThan.Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("failed to delete old audit entries: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get affected rows: %w", err)
	}
	if count > 0 {
		log.Printf("[DEBUG] deleted %d audit entries older than %s", count, olderThan.Format(time.RFC3339))
	}
	return count, nil
}
