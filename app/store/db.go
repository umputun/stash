package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/go-pkgz/lgr"
	_ "github.com/jackc/pgx/v5/stdlib" // postgresql driver
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // sqlite driver

	"github.com/umputun/stash/app/enum"
)

// Encryptor defines the interface for encrypting and decrypting secret values.
type Encryptor interface {
	Encrypt(value []byte) ([]byte, error)
	Decrypt(encrypted []byte) ([]byte, error)
}

// Store implements key-value storage using SQLite or PostgreSQL.
type Store struct {
	db        *sqlx.DB
	dbType    DBType
	mu        RWLocker
	encryptor Encryptor // for encrypting secrets (nil = secrets disabled)
}

// Option configures Store behavior.
type Option func(*Store)

// WithEncryptor enables secrets encryption with the given encryptor.
func WithEncryptor(enc Encryptor) Option {
	return func(s *Store) {
		s.encryptor = enc
	}
}

// SecretsEnabled returns true if the store is configured for secrets encryption.
func (s *Store) SecretsEnabled() bool {
	return s.encryptor != nil
}

// New creates a new Store with the given database URL.
// Automatically detects database type from URL:
// - postgres:// or postgresql:// -> PostgreSQL
// - everything else -> SQLite
func New(dbURL string, opts ...Option) (*Store, error) {
	dbType := detectDBType(dbURL)

	var db *sqlx.DB
	var err error
	var locker RWLocker

	switch dbType {
	case DBTypePostgres:
		db, err = connectPostgres(dbURL)
		locker = noopLocker{}
	default:
		db, err = connectSQLite(dbURL)
		locker = &sync.RWMutex{}
	}

	if err != nil {
		return nil, err
	}

	s := &Store{db: db, dbType: dbType, mu: locker}

	// apply options
	for _, opt := range opts {
		opt(s)
	}

	if err := s.createSchema(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Printf("[DEBUG] initialized %s store", s.dbTypeName())
	return s, nil
}

// detectDBType determines database type from URL.
func detectDBType(url string) DBType {
	lower := strings.ToLower(url)
	if strings.HasPrefix(lower, "postgres://") || strings.HasPrefix(lower, "postgresql://") {
		return DBTypePostgres
	}
	return DBTypeSQLite
}

// connectSQLite establishes SQLite connection with pragmas.
func connectSQLite(dbPath string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to sqlite: %w", err)
	}

	// set pragmas for performance and reliability
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA cache_size=1000",
		"PRAGMA foreign_keys=ON",
	}
	for _, pragma := range pragmas {
		if _, err := db.Exec(pragma); err != nil { //nolint:noctx // init-time, no context available
			_ = db.Close()
			return nil, fmt.Errorf("failed to set pragma %q: %w", pragma, err)
		}
	}

	// limit connections for SQLite (single writer)
	db.SetMaxOpenConns(1)

	return db, nil
}

// connectPostgres establishes PostgreSQL connection.
func connectPostgres(dbURL string) (*sqlx.DB, error) {
	db, err := sqlx.Connect("pgx", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}

	// set reasonable connection pool defaults
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	return db, nil
}

// createSchema creates the kv, sessions, and audit_log tables if they don't exist.
func (s *Store) createSchema() error {
	var kvSchema, sessionsSchema, auditSchema string
	switch s.dbType {
	case DBTypePostgres:
		kvSchema = `
			CREATE TABLE IF NOT EXISTS kv (
				key TEXT PRIMARY KEY,
				value BYTEA NOT NULL,
				format TEXT NOT NULL DEFAULT 'text',
				created_at TIMESTAMP DEFAULT NOW(),
				updated_at TIMESTAMP DEFAULT NOW()
			)`
		sessionsSchema = `
			CREATE TABLE IF NOT EXISTS sessions (
				token TEXT PRIMARY KEY,
				username TEXT NOT NULL,
				expires_at TIMESTAMPTZ NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
			CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username)`
		auditSchema = `
			CREATE TABLE IF NOT EXISTS audit_log (
				id SERIAL PRIMARY KEY,
				timestamp TIMESTAMPTZ NOT NULL,
				action TEXT NOT NULL,
				key TEXT NOT NULL,
				actor TEXT NOT NULL,
				actor_type TEXT NOT NULL,
				result TEXT NOT NULL,
				ip TEXT,
				user_agent TEXT,
				value_size INTEGER,
				request_id TEXT
			);
			CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
			CREATE INDEX IF NOT EXISTS idx_audit_key ON audit_log(key);
			CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
			CREATE INDEX IF NOT EXISTS idx_audit_ts_key ON audit_log(timestamp, key)`
	default:
		kvSchema = `
			CREATE TABLE IF NOT EXISTS kv (
				key TEXT PRIMARY KEY,
				value BLOB NOT NULL,
				format TEXT NOT NULL DEFAULT 'text',
				created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
				updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
			)`
		sessionsSchema = `
			CREATE TABLE IF NOT EXISTS sessions (
				token TEXT PRIMARY KEY,
				username TEXT NOT NULL,
				expires_at DATETIME NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
			CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username)`
		auditSchema = `
			CREATE TABLE IF NOT EXISTS audit_log (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				timestamp TEXT NOT NULL,
				action TEXT NOT NULL,
				key TEXT NOT NULL,
				actor TEXT NOT NULL,
				actor_type TEXT NOT NULL,
				result TEXT NOT NULL,
				ip TEXT,
				user_agent TEXT,
				value_size INTEGER,
				request_id TEXT
			);
			CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
			CREATE INDEX IF NOT EXISTS idx_audit_key ON audit_log(key);
			CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor);
			CREATE INDEX IF NOT EXISTS idx_audit_ts_key ON audit_log(timestamp, key)`
	}

	if _, err := s.db.Exec(kvSchema); err != nil { //nolint:noctx // init-time, no context available
		return fmt.Errorf("failed to create kv table: %w", err)
	}
	if _, err := s.db.Exec(sessionsSchema); err != nil { //nolint:noctx // init-time, no context available
		return fmt.Errorf("failed to create sessions table: %w", err)
	}
	if _, err := s.db.Exec(auditSchema); err != nil { //nolint:noctx // init-time, no context available
		return fmt.Errorf("failed to create audit_log table: %w", err)
	}
	return nil
}

// migrate runs database migrations for existing installations.
// adds missing columns that were introduced in later versions.
func (s *Store) migrate() error {
	// check if format column exists
	hasFormat, err := s.hasColumn("kv", "format")
	if err != nil {
		return fmt.Errorf("failed to check format column: %w", err)
	}

	if !hasFormat {
		log.Printf("[INFO] migrating database: adding format column to kv table")
		alter := "ALTER TABLE kv ADD COLUMN format TEXT NOT NULL DEFAULT 'text'"
		if _, err := s.db.Exec(alter); err != nil { //nolint:noctx // init-time, no context available
			return fmt.Errorf("failed to add format column: %w", err)
		}
	}

	return nil
}

// hasColumn checks if a column exists in the given table.
func (s *Store) hasColumn(table, column string) (bool, error) {
	var query string
	switch s.dbType {
	case DBTypePostgres:
		query = `SELECT EXISTS (
			SELECT 1 FROM information_schema.columns
			WHERE table_name = $1 AND column_name = $2
		)`
	default:
		// sqlite: use pragma table_info which returns (cid, name, type, notnull, dflt_value, pk)
		var columns []struct {
			CID        int            `db:"cid"`
			Name       string         `db:"name"`
			Type       string         `db:"type"`
			NotNull    int            `db:"notnull"`
			DfltValue  sql.NullString `db:"dflt_value"`
			PrimaryKey int            `db:"pk"`
		}
		if err := s.db.Select(&columns, "PRAGMA table_info("+table+")"); err != nil {
			return false, fmt.Errorf("failed to get table info: %w", err)
		}
		for _, col := range columns {
			if col.Name == column {
				return true, nil
			}
		}
		return false, nil
	}

	var exists bool
	if err := s.db.Get(&exists, query, table, column); err != nil {
		return false, fmt.Errorf("failed to check column existence: %w", err)
	}
	return exists, nil
}

// dbTypeName returns human-readable database type name.
func (s *Store) dbTypeName() string {
	switch s.dbType {
	case DBTypePostgres:
		return "postgres"
	default:
		return "sqlite"
	}
}

// Get retrieves the value for the given key.
// Returns ErrNotFound if the key does not exist.
// Returns ErrSecretsNotConfigured if key is a secret path but secrets are not enabled.
func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// check if trying to access secret without key configured
	if IsSecret(key) && !s.SecretsEnabled() {
		return nil, ErrSecretsNotConfigured
	}

	var value []byte
	query := s.adoptQuery("SELECT value FROM kv WHERE key = ?")
	err := s.db.GetContext(ctx, &value, query, key)
	if errors.Is(err, sql.ErrNoRows) {
		log.Printf("[DEBUG] get key %q: not found", key)
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get key %q: %w", key, err)
	}

	// decrypt if this is a secret (skip if ZK-encrypted - client handles decryption)
	if IsSecret(key) && !IsZKEncrypted(value) {
		decrypted, err := s.encryptor.Decrypt(value)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt key %q: %w", key, err)
		}
		value = decrypted
	}

	log.Printf("[DEBUG] get key %q: %d bytes", key, len(value))
	return value, nil
}

// GetWithFormat retrieves the value and format for the given key.
// Returns ErrNotFound if the key does not exist.
// Returns ErrSecretsNotConfigured if key is a secret path but secrets are not enabled.
func (s *Store) GetWithFormat(ctx context.Context, key string) ([]byte, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// check if trying to access secret without key configured
	if IsSecret(key) && !s.SecretsEnabled() {
		return nil, "", ErrSecretsNotConfigured
	}

	var result struct {
		Value  []byte `db:"value"`
		Format string `db:"format"`
	}
	query := s.adoptQuery("SELECT value, format FROM kv WHERE key = ?")
	err := s.db.GetContext(ctx, &result, query, key)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", fmt.Errorf("failed to get key %q: %w", key, err)
	}

	// decrypt if this is a secret (skip if ZK-encrypted - client handles decryption)
	if IsSecret(key) && !IsZKEncrypted(result.Value) {
		decrypted, err := s.encryptor.Decrypt(result.Value)
		if err != nil {
			return nil, "", fmt.Errorf("failed to decrypt key %q: %w", key, err)
		}
		result.Value = decrypted
	}

	return result.Value, result.Format, nil
}

// GetInfo retrieves metadata for the given key without loading the value.
// Returns ErrNotFound if the key does not exist.
// Returns ErrSecretsNotConfigured if key is a secret path but secrets are not enabled.
func (s *Store) GetInfo(ctx context.Context, key string) (KeyInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// check if trying to access secret without key configured
	if IsSecret(key) && !s.SecretsEnabled() {
		return KeyInfo{}, ErrSecretsNotConfigured
	}

	var result struct {
		KeyInfo
		ValuePrefix []byte `db:"value_prefix"`
	}
	query := s.adoptQuery(`SELECT key, length(value) as size, format, created_at, updated_at,
		SUBSTR(value, 1, 5) as value_prefix FROM kv WHERE key = ?`)
	err := s.db.GetContext(ctx, &result, query, key)
	if errors.Is(err, sql.ErrNoRows) {
		return KeyInfo{}, ErrNotFound
	}
	if err != nil {
		return KeyInfo{}, fmt.Errorf("failed to get info for key %q: %w", key, err)
	}

	// set secret flag based on key path
	result.Secret = IsSecret(key)
	// set ZK encrypted flag based on value prefix
	result.ZKEncrypted = IsZKEncrypted(result.ValuePrefix)

	return result.KeyInfo, nil
}

// Set stores the value for the given key with the specified format.
// Creates a new key or updates an existing one.
// If format is empty, defaults to "text".
// Returns ErrSecretsNotConfigured if key is a secret path but secrets are not enabled.
// Returns (true, nil) if a new key was created, (false, nil) if an existing key was updated.
func (s *Store) Set(ctx context.Context, key string, value []byte, format string) (created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// check if trying to store secret without key configured
	if IsSecret(key) && !s.SecretsEnabled() {
		return false, ErrSecretsNotConfigured
	}

	if format == "" {
		format = "text"
	}

	// reject invalid ZK payloads in secrets paths
	if IsSecret(key) && IsZKEncrypted(value) && !IsValidZKPayload(value) {
		return false, ErrInvalidZKPayload
	}

	// encrypt secrets (skip if already ZK-encrypted)
	storeValue := value
	if IsSecret(key) && !IsZKEncrypted(value) {
		var encrypted []byte
		encrypted, err = s.encryptor.Encrypt(value)
		if err != nil {
			return false, fmt.Errorf("failed to encrypt key %q: %w", key, err)
		}
		storeValue = encrypted
	}

	now := time.Now().UTC()

	// try insert first
	insertQuery := s.adoptQuery(`INSERT INTO kv (key, value, format, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`)
	_, err = s.db.ExecContext(ctx, insertQuery, key, storeValue, format, now, now)
	if err == nil {
		log.Printf("[DEBUG] created key %q: %d bytes, format=%s", key, len(value), format)
		return true, nil
	}

	// check if it's a unique constraint violation (key exists)
	if !isUniqueViolation(err) {
		return false, fmt.Errorf("failed to set key %q: %w", key, err)
	}

	// update existing key
	updateQuery := s.adoptQuery(`UPDATE kv SET value = ?, format = ?, updated_at = ? WHERE key = ?`)
	if _, err = s.db.ExecContext(ctx, updateQuery, storeValue, format, now, key); err != nil {
		return false, fmt.Errorf("failed to update key %q: %w", key, err)
	}
	log.Printf("[DEBUG] updated key %q: %d bytes, format=%s", key, len(value), format)
	return false, nil
}

// isUniqueViolation checks if error is a unique constraint violation.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	// sQLite
	if strings.Contains(errStr, "UNIQUE constraint failed") {
		return true
	}
	// postgreSQL
	if strings.Contains(errStr, "duplicate key value") {
		return true
	}
	return false
}

// SetWithVersion stores the value only if the key's updated_at matches expectedVersion.
// Returns *ConflictError with current state if the key was modified since expectedVersion.
// If expectedVersion is zero, behaves like regular Set (no version check).
// Returns ErrSecretsNotConfigured if key is a secret path but secrets are not enabled.
func (s *Store) SetWithVersion(ctx context.Context, key string, value []byte, format string, expectedVersion time.Time) error {
	if expectedVersion.IsZero() {
		_, err := s.Set(ctx, key, value, format)
		return err
	}

	// check if trying to store secret without key configured
	if IsSecret(key) && !s.SecretsEnabled() {
		return ErrSecretsNotConfigured
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if format == "" {
		format = "text"
	}

	// reject invalid ZK payloads in secrets paths
	if IsSecret(key) && IsZKEncrypted(value) && !IsValidZKPayload(value) {
		return ErrInvalidZKPayload
	}

	// encrypt secrets (skip if already ZK-encrypted)
	storeValue := value
	if IsSecret(key) && !IsZKEncrypted(value) {
		encrypted, err := s.encryptor.Encrypt(value)
		if err != nil {
			return fmt.Errorf("failed to encrypt key %q: %w", key, err)
		}
		storeValue = encrypted
	}

	now := time.Now().UTC()

	// atomic update: only succeeds if version matches
	query := s.adoptQuery(`UPDATE kv SET value = ?, format = ?, updated_at = ? WHERE key = ? AND updated_at = ?`)
	result, err := s.db.ExecContext(ctx, query, storeValue, format, now, key, expectedVersion)
	if err != nil {
		return fmt.Errorf("failed to update key %q: %w", key, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}

	if rows == 0 {
		// either key doesn't exist or version mismatch - fetch current state
		return s.buildConflictError(ctx, key, expectedVersion)
	}

	return nil
}

// buildConflictError fetches current state and builds a ConflictError.
// must be called with lock held.
func (s *Store) buildConflictError(ctx context.Context, key string, attemptedVersion time.Time) error {
	var result struct {
		Value     []byte    `db:"value"`
		Format    string    `db:"format"`
		UpdatedAt time.Time `db:"updated_at"`
	}
	query := s.adoptQuery("SELECT value, format, updated_at FROM kv WHERE key = ?")
	err := s.db.GetContext(ctx, &result, query, key)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound // key was deleted
	}
	if err != nil {
		return fmt.Errorf("failed to get current state for conflict: %w", err)
	}

	// decrypt value if this is a secret key (skip if ZK-encrypted)
	currentValue := result.Value
	if IsSecret(key) && s.encryptor != nil && !IsZKEncrypted(result.Value) {
		if decrypted, decErr := s.encryptor.Decrypt(result.Value); decErr == nil {
			currentValue = decrypted
		} else {
			log.Printf("[WARN] failed to decrypt secret value for conflict on key %q: %v", key, decErr)
		}
	}

	return &ConflictError{
		Info: ConflictInfo{
			CurrentValue:     currentValue,
			CurrentFormat:    result.Format,
			CurrentVersion:   result.UpdatedAt,
			AttemptedVersion: attemptedVersion,
		},
	}
}

// Delete removes the key from the store.
// Returns ErrNotFound if the key does not exist.
func (s *Store) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := s.adoptQuery("DELETE FROM kv WHERE key = ?")
	result, err := s.db.ExecContext(ctx, query, key)
	if err != nil {
		return fmt.Errorf("failed to delete key %q: %w", key, err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check affected rows: %w", err)
	}
	if rows == 0 {
		log.Printf("[DEBUG] delete key %q: not found", key)
		return ErrNotFound
	}
	log.Printf("[DEBUG] delete key %q: ok", key)
	return nil
}

// List returns metadata for all keys, with optional filtering by secret flag.
// SecretsFilterAll returns all keys, SecretsFilterSecretsOnly returns only secrets,
// SecretsFilterKeysOnly returns only non-secrets.
func (s *Store) List(ctx context.Context, filter enum.SecretsFilter) ([]KeyInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	type keyWithPrefix struct {
		KeyInfo
		ValuePrefix []byte `db:"value_prefix"`
	}
	var keys []keyWithPrefix
	query := s.adoptQuery(`SELECT key, length(value) as size, format, created_at, updated_at,
		SUBSTR(value, 1, 5) as value_prefix FROM kv ORDER BY updated_at DESC`)
	if err := s.db.SelectContext(ctx, &keys, query); err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	// set secret/ZK flags and filter if needed
	result := make([]KeyInfo, 0, len(keys))
	for i := range keys {
		keys[i].Secret = IsSecret(keys[i].Key)
		keys[i].ZKEncrypted = IsZKEncrypted(keys[i].ValuePrefix)

		switch filter {
		case enum.SecretsFilterSecretsOnly:
			if !keys[i].Secret {
				continue // want secrets only, this is not a secret
			}
		case enum.SecretsFilterKeysOnly:
			if keys[i].Secret {
				continue // want non-secrets only, this is a secret
			}
		}
		result = append(result, keys[i].KeyInfo)
	}

	log.Printf("[DEBUG] list keys: %d keys (filter=%s)", len(result), filter)
	return result, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("failed to close database: %w", err)
	}
	return nil
}

// adoptQuery converts SQLite query syntax to PostgreSQL:
// - placeholders: ? → $1, $2, ...
// - functions: length( → octet_length(
// - case: excluded. → EXCLUDED.
func (s *Store) adoptQuery(query string) string {
	if s.dbType != DBTypePostgres {
		return query
	}

	// function and keyword mappings
	query = strings.ReplaceAll(query, "length(", "octet_length(")
	query = strings.ReplaceAll(query, "excluded.", "EXCLUDED.")

	// placeholder conversion
	result := make([]byte, 0, len(query)+10)
	paramNum := 1
	for i := range len(query) {
		if query[i] != '?' {
			result = append(result, query[i])
			continue
		}
		result = append(result, '$')
		result = append(result, strconv.Itoa(paramNum)...)
		paramNum++
	}
	return string(result)
}

// CreateSession stores a new session in the database.
func (s *Store) CreateSession(ctx context.Context, token, username string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := s.adoptQuery(`INSERT INTO sessions (token, username, expires_at) VALUES (?, ?, ?)
		ON CONFLICT(token) DO UPDATE SET username = excluded.username, expires_at = excluded.expires_at`)
	if _, err := s.db.ExecContext(ctx, query, token, username, expiresAt.UTC()); err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	log.Printf("[DEBUG] create session for user %q", username)
	return nil
}

// GetSession retrieves session data by token.
// Returns ErrNotFound if the session doesn't exist or is expired.
func (s *Store) GetSession(ctx context.Context, token string) (username string, expiresAt time.Time, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result struct {
		Username  string    `db:"username"`
		ExpiresAt time.Time `db:"expires_at"`
	}
	query := s.adoptQuery("SELECT username, expires_at FROM sessions WHERE token = ?")
	if err := s.db.GetContext(ctx, &result, query, token); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", time.Time{}, ErrNotFound
		}
		return "", time.Time{}, fmt.Errorf("failed to get session: %w", err)
	}

	// check expiration and normalize to UTC for consistency
	expiresUTC := result.ExpiresAt.UTC()
	if time.Now().UTC().After(expiresUTC) {
		return "", time.Time{}, ErrNotFound
	}

	return result.Username, expiresUTC, nil
}

// DeleteSession removes a session by token.
// Returns nil even if the session doesn't exist (idempotent).
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := s.adoptQuery("DELETE FROM sessions WHERE token = ?")
	if _, err := s.db.ExecContext(ctx, query, token); err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	maskedToken := "****"
	if len(token) > 4 {
		maskedToken = token[:4] + "****"
	}
	log.Printf("[DEBUG] delete session %s", maskedToken)
	return nil
}

// DeleteAllSessions removes all sessions from the database.
func (s *Store) DeleteAllSessions(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions"); err != nil {
		return fmt.Errorf("failed to delete all sessions: %w", err)
	}
	log.Printf("[DEBUG] delete all sessions")
	return nil
}

// DeleteSessionsByUsername removes all sessions for a specific user.
// Returns nil even if the user has no sessions (idempotent).
func (s *Store) DeleteSessionsByUsername(ctx context.Context, username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := s.adoptQuery("DELETE FROM sessions WHERE username = ?")
	if _, err := s.db.ExecContext(ctx, query, username); err != nil {
		return fmt.Errorf("failed to delete sessions for user %q: %w", username, err)
	}
	log.Printf("[DEBUG] delete sessions for user %q", username)
	return nil
}

// DeleteExpiredSessions removes all expired sessions.
// Returns the number of sessions deleted.
func (s *Store) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	query := s.adoptQuery("DELETE FROM sessions WHERE expires_at < ?")
	result, err := s.db.ExecContext(ctx, query, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("failed to delete expired sessions: %w", err)
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get affected rows: %w", err)
	}
	if count > 0 {
		log.Printf("[DEBUG] delete expired sessions: %d deleted", count)
	}
	return count, nil
}
