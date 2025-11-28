# Stash Project

Simple key-value configuration service - a minimal alternative to Consul KV or etcd.

## Project Structure

- **app/main.go** - Entry point with CLI subcommands (server, restore), logging, signal handling
- **app/main_test.go** - Integration tests
- **app/server/** - HTTP server with routegroup
  - `server.go` - Server struct, config, routes, graceful shutdown, GitStore interface
  - `handlers.go` - HTTP handlers for KV API operations (with git integration)
  - `web.go` - Web UI handlers, templates, static file serving, per-user permission checks
  - `auth.go` - Authentication: YAML config (users + tokens), sessions, middleware, prefix-based ACL
  - `static/` - Embedded CSS, JS, HTMX library
  - `templates/` - Embedded HTML templates (base, index, login, partials)
  - `mocks/` - Generated mocks (moq)
- **app/store/** - Database storage layer (SQLite/PostgreSQL)
  - `store.go` - Interface, types (KeyInfo), errors
  - `sqlite.go` - Unified Store with SQLite and PostgreSQL support
  - `cached.go` - Loading cache wrapper using lcw
- **app/git/** - Git versioning for key-value storage
  - `git.go` - Git operations using go-git (commit, push, pull, checkout, readall)
  - `git_test.go` - Unit tests

## Key Dependencies

- **CLI**: `github.com/jessevdk/go-flags`
- **Logging**: `github.com/go-pkgz/lgr`
- **HTTP**: `github.com/go-pkgz/routegroup`, `github.com/go-pkgz/rest`
- **Database**: `github.com/jmoiron/sqlx`, `modernc.org/sqlite`, `github.com/jackc/pgx/v5`
- **Git**: `github.com/go-git/go-git/v5`
- **Cache**: `github.com/go-pkgz/lcw/v2`
- **Testing**: `github.com/stretchr/testify`

## Build & Test

```bash
make build    # build binary
make test     # run tests
make lint     # run linter
make run      # run with logging enabled
```

**Note**: CSS, JS, and HTML templates are embedded at compile time. After modifying any static files or templates, you must rebuild (`make build`) and restart the server to see changes.

## API

```
GET    /kv/           # list keys (returns JSON array of KeyInfo, supports ?prefix=)
GET    /kv/{key...}   # get value (returns raw body, 200/404)
PUT    /kv/{key...}   # set value (body is value, returns 200)
DELETE /kv/{key...}   # delete key (returns 204/404)
GET    /ping          # health check (returns "pong")
```

Keys can contain slashes (e.g., `app/config/database`).

List endpoint returns only keys the caller has read permission for when auth is enabled.

## Web UI Routes

```
GET    /                         # main page with key list
GET    /web/keys                 # HTMX partial: key table (supports ?search=)
GET    /web/keys/new             # HTMX partial: new key form
GET    /web/keys/view/{key...}   # HTMX partial: view modal
GET    /web/keys/edit/{key...}   # HTMX partial: edit form
POST   /web/keys                 # create new key
PUT    /web/keys/{key...}        # update key value
DELETE /web/keys/{key...}        # delete key
POST   /web/theme                # toggle theme (light/dark)
```

## Auth Routes (when enabled)

```
GET    /login                    # login form
POST   /login                    # authenticate, set session cookie
POST   /logout                   # clear session, redirect to login
```

## CLI Commands

- `stash server` - Run the HTTP server
- `stash restore --rev=<commit>` - Restore database from git revision

## Development Notes

- Consumer-side interfaces (KVStore, GitStore defined in server package)
- Return concrete types, accept interfaces
- Database type auto-detected from URL (postgres:// vs file path)
- SQLite: WAL mode, SetMaxOpenConns(1), busy timeout, sync.RWMutex for locking
- PostgreSQL: standard connection pool, MVCC handles concurrency (no app-level locking)
- Query placeholders: SQLite uses `?`, PostgreSQL uses `$1, $2, ...` (adoptQuery converts)
- Git versioning: optional, logs WARN on failures (DB is source of truth)
- Git storage: path-based with `.val` suffix (app/config → .history/app/config.val)
- Auth: YAML config file with users (web UI) and tokens (API), both use prefix-based ACL
- Auth flow: username+password login creates session, session tracks username for permission checks
- Permissions: prefix patterns (*, foo/*, exact) with access levels (r, w, rw), longest match wins
- Web handlers check permissions server-side (not just UI conditions)
- Cache: optional loading cache wrapper, populated on reads, invalidated on writes
- Keep it simple - no over-engineering
