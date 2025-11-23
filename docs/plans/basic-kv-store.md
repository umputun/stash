# Basic KV Store Implementation

## Overview

Implement core key-value storage functionality for stash:
- SQLite-based persistent storage using sqlx + modernc.org/sqlite
- HTTP REST API using go-pkgz/routegroup
- Basic CRUD operations (no TTL, no prefix listing, no auth)

## Context (from discovery)

**Files involved:**
- `app/main.go` - entry point, already has CLI options and signal handling
- `app/store/sqlite.go` - new SQLite store implementation
- `app/server/server.go` - new HTTP server with routegroup

**Patterns from reference projects:**
- cronn: SQLite store with sqlx, WAL mode, busy timeout pragmas
- secrets: server structure with Run(ctx), routes() method, graceful shutdown
- Both: consumer-side interfaces, return concrete types

**Dependencies to add:**
- `github.com/jmoiron/sqlx`
- `modernc.org/sqlite`
- `github.com/go-pkgz/routegroup`
- `github.com/go-pkgz/rest`

## Iterative Development Approach

- Complete each iteration fully before moving to the next
- Write tests alongside implementation
- Run tests and linter after each change

## Progress Tracking

- Mark completed items with `[x]`
- Add newly discovered tasks with + prefix
- Document issues/blockers with ! prefix

## Implementation Steps

### Iteration 1: Store Layer [COMPLETED]

- [x] Create `app/store/store.go` with KV struct and error definitions
- [x] Create `app/store/sqlite.go` with SQLite implementation:
  - NewSQLite(dbPath) constructor with schema creation (CREATE TABLE IF NOT EXISTS)
  - Get(key) method
  - Set(key, value) method using INSERT ON CONFLICT UPDATE (upsert with updated_at)
  - Delete(key) method
  - Close() method
  - WAL mode, busy timeout pragmas, SetMaxOpenConns(1)
- [x] Create `app/store/sqlite_test.go` with tests for all operations including errors
- [x] Run tests to verify store layer works

### Iteration 2: Server Layer [COMPLETED]

- [x] Create `app/server/server.go` with:
  - Server struct holding store dependency
  - Config struct for server options
  - New(store, cfg) constructor
  - Run(ctx) method with graceful shutdown
  - routes() method setting up routegroup
- [x] Create `app/server/handlers.go` with HTTP handlers:
  - GET /kv/{key...} - get value (supports slashes in keys)
  - PUT /kv/{key...} - set value (body is value)
  - DELETE /kv/{key...} - delete key
- [x] Add middleware: rest.RealIP, rest.Recoverer, rest.Ping, rest.SizeLimit(1MB), rest.Throttle, rest.Trace, rest.AppInfo
- [x] Run tests to verify server compiles

### Iteration 3: Server Tests [COMPLETED]

- [x] Create `app/server/server_test.go` with httptest-based tests
- [x] Test GET existing key returns 200 + value
- [x] Test GET missing key returns 404
- [x] Test PUT sets key returns 200
- [x] Test DELETE removes key returns 204
- [x] Test DELETE missing key returns 404
- [x] Test keys with slashes work correctly
- [x] Test /ping endpoint returns pong
- [x] Run full test suite

### Iteration 4: Wire Up Main [COMPLETED]

- [x] Update `app/main.go` run() function:
  - Initialize SQLite store with opts.Store path
  - Create server with store and config from opts
  - Start server, handle errors
- [x] Add defer store.Close()
- [x] Test manually with curl
- [x] Run linter and fix issues

### Iteration 5: Documentation & Cleanup [COMPLETED]

- [x] Update README.md with usage examples
- [x] Final test run with race detector
- [x] Verify build works

## Technical Details

### Data Model

```sql
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Store Interface (consumer-side, in server package)

```go
type KVStore interface {
    Get(key string) ([]byte, error)
    Set(key string, value []byte) error
    Delete(key string) error
}
```

### API Endpoints

| Method | Path | Request | Response | Status |
|--------|------|---------|----------|--------|
| GET | /kv/{key} | - | value body | 200/404 |
| PUT | /kv/{key} | value body | - | 200 |
| DELETE | /kv/{key} | - | - | 204/404 |

Note: PUT always returns 200 (idempotent operation, no create/update distinction).

### Error Handling

- Store returns `ErrNotFound` for missing keys
- Server maps `ErrNotFound` to 404
- Other errors return 500 with logged details
