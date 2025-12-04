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
  - `verify.go` - JSON schema validation for auth config (embedded schema)
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

## Enum Types

The project uses `github.com/go-pkgz/enum` for type-safe enums defined in `app/enum/enum.go`:

- **Format**: text, json, yaml, xml, toml, ini, hcl, shell (for syntax highlighting)
- **ViewMode**: grid, cards (UI display modes)
- **SortMode**: updated, key, size, created
- **Theme**: system, light, dark
- **Permission**: none, r, w, rw
- **DbType**: sqlite, postgres

Enums are generated with `//go:generate` and support String(), MarshalText/UnmarshalText.

## Key Dependencies

- **CLI**: `github.com/jessevdk/go-flags`
- **Logging**: `github.com/go-pkgz/lgr`
- **HTTP**: `github.com/go-pkgz/routegroup`, `github.com/go-pkgz/rest`
- **Database**: `github.com/jmoiron/sqlx`, `modernc.org/sqlite`, `github.com/jackc/pgx/v5`
- **Git**: `github.com/go-git/go-git/v5`
- **Cache**: `github.com/go-pkgz/lcw/v2`
- **File watching**: `github.com/fsnotify/fsnotify`
- **Testing**: `github.com/stretchr/testify`
- **Enums**: `github.com/go-pkgz/enum`

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
POST   /web/view-mode            # toggle view mode (grid/cards)
POST   /web/sort                 # cycle sort order
```

## Web UI Structure

- Templates in `app/server/web/templates/` with partials in `partials/` subdirectory
- Form has format selector dropdown (`select[name="format"]`)
- View modal shows format badge (`.format-badge`) except for text format
- Syntax highlighting uses Chroma (`.highlighted-code` class)
- Modals: `#main-modal` for view/edit/create, `#confirm-modal` for delete confirmation
- Modal close: Escape key or clicking backdrop

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
- Sessions: stored in database (sessions table), persist across server restarts, background cleanup of expired sessions
- Permissions: prefix patterns (*, foo/*, exact) with access levels (r, w, rw), longest match wins
- Auth hot-reload: fsnotify watches directory (not file) for atomic rename support, debounces 100ms
- Auth hot-reload invalidates all sessions on config change, rejects invalid configs
- Web handlers check permissions server-side (not just UI conditions)
- Cache: optional loading cache wrapper, populated on reads, invalidated on writes
- Keep it simple - no over-engineering

## Testing Selectors (Playwright)

**Table View:**
- `td.key-cell` - key names in rows
- `button.btn-edit`, `button.btn-danger` - action buttons per row
- `tr:has-text("key-name")` - target specific row

**Card View:**
- `.key-card` - individual cards
- `.cards-container` - card container (presence indicates card mode)

**Modals:**
- `#main-modal` - view/edit/create modal backdrop
- `#modal-content` - modal content container
- `#confirm-modal` - delete confirmation modal
- `#confirm-delete-btn` - confirm delete button

**Forms:**
- `input[name="key"]`, `textarea[name="value"]` - key/value inputs
- `select[name="format"]` - format dropdown
- `#modal-content button[type="submit"]` - submit button

**Header Controls:**
- `form[hx-post="/web/theme"] button` - theme toggle
- `button[hx-post="/web/view-mode"]` - view mode toggle
- `.sort-button` - sort toggle
- `input[name="search"]` - search input (300ms debounce)
