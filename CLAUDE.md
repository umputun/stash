# Stash Project

Simple key-value configuration service - a minimal alternative to Consul KV or etcd.

## Project Structure

- **app/main.go** - Entry point with CLI subcommands (server, restore), logging, signal handling
- **app/main_test.go** - Integration tests
- **app/server/** - HTTP server with routegroup
  - `server.go` - Server struct, config, routes, graceful shutdown, GitStore interface
  - `handlers.go` - HTTP handlers for KV API operations (with git integration)
  - `audit/` - Audit package
    - `audit.go` - Middleware for audit logging, Store and Auth interfaces
    - `handler.go` - Handler for POST /audit/query endpoint (admin only)
    - `mocks/` - Generated mocks
  - `web.go` - Web UI handlers, templates, static file serving, per-user permission checks
  - `web/audit.go` - Audit web UI handler (full page and HTMX partials)
  - `auth/` - Authentication package
    - `auth.go` - Service struct, session management, user/token validation, permission checks
    - `config.go` - Config types (User, TokenACL, PermissionConfig), YAML loading
    - `middleware.go` - SessionMiddleware, TokenMiddleware, token extraction
    - `mocks/` - Generated mocks
  - `sse/` - Server-Sent Events for real-time key subscriptions
    - `sse.go` - Service struct, OnSession callback, Publish method, ServeHTTP handler
    - `sse_test.go` - Unit tests
    - `mocks/` - Generated mocks
  - `verify.go` - JSON schema validation for auth config (embedded schema)
  - `static/` - Embedded CSS, JS, HTMX library
  - `templates/` - Embedded HTML templates (base, index, login, audit, partials)
  - `mocks/` - Generated mocks (moq)
- **app/store/** - Database storage layer (SQLite/PostgreSQL)
  - `store.go` - Interface, types (KeyInfo with Secret/ZKEncrypted fields), errors
  - `db.go` - Unified Store with SQLite and PostgreSQL support
  - `cached.go` - Loading cache wrapper using lcw
  - `crypto.go` - Secrets encryption (NaCl secretbox + Argon2id)
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
- **SecretsFilter**: all, secrets, keys (for API list filtering)
- **AuditAction**: read, create, update, delete
- **AuditResult**: success, denied, not_found
- **ActorType**: user, token, public

Enums are generated with `//go:generate` and support String(), MarshalText/UnmarshalText.

## Key Dependencies

- **CLI**: `github.com/jessevdk/go-flags`
- **Logging**: `github.com/go-pkgz/lgr`
- **HTTP**: `github.com/go-pkgz/routegroup`, `github.com/go-pkgz/rest`
- **Database**: `github.com/jmoiron/sqlx`, `modernc.org/sqlite`, `github.com/jackc/pgx/v5`
- **Git**: `github.com/go-git/go-git/v5`
- **Cache**: `github.com/go-pkgz/lcw/v2`
- **Crypto**: `golang.org/x/crypto` (argon2, nacl/secretbox)
- **File watching**: `github.com/fsnotify/fsnotify`
- **Testing**: `github.com/stretchr/testify`
- **Enums**: `github.com/go-pkgz/enum`

## Build & Test

```bash
make build    # build binary
make test     # run tests
make lint     # run linter
make e2e      # run e2e UI tests (acceptance testing)
make run      # run with logging enabled
```

**Note**: CSS, JS, and HTML templates are embedded at compile time. After modifying any static files or templates, you must rebuild (`make build`) and restart the server to see changes.

**Local testing with auth**: Use `auth-private.yml` (gitignored) with users: admin, readonly, scoped (all password: "testpass"). Run with `./stash server --auth.file=auth-private.yml --auth.hot-reload --dbg`

**Manual API testing**: Use `requests.http` with JetBrains IDE or CLI:
```bash
# JetBrains HTTP Client CLI (ijhttp)
ijhttp requests.http -e local -v http-client.env.json

# or with Docker
docker run --rm -v $(pwd):/workdir jetbrains/intellij-http-client \
  -e local -v http-client.env.json requests.http
```

**Background server for Playwright/browser testing**:
```bash
# build first
make build

# start server in background (separate command, not chained with &&)
./stash server --dbg --server.address=:18080 --db=/tmp/stash-test.db &

# with git enabled
./stash server --dbg --server.address=:18080 --db=/tmp/stash-test.db --git.enabled --git.path=/tmp/stash-git &

# with secrets enabled (min 16 chars key)
./stash server --dbg --server.address=:18080 --db=/tmp/stash-test.db \
  --secrets.key="test-secret-key-min-16-chars" &

# verify running (run after server start)
sleep 2; curl -s http://localhost:18080/ping

# cleanup after testing
pkill -f "stash server.*18080"; rm -f /tmp/stash-test.db
```

## API

```
GET    /kv/                      # list keys (returns JSON array of KeyInfo, supports ?prefix=)
GET    /kv/history/{key...}      # get key history (requires git, returns JSON array)
GET    /kv/{key...}              # get value (returns raw body, 200/404)
PUT    /kv/{key...}              # set value (body is value, returns 200)
DELETE /kv/{key...}              # delete key (returns 204/404)
GET    /kv/subscribe/{key...}    # SSE subscription (exact key or prefix with /* or /)
GET    /ping                     # health check (returns "pong")
```

Keys can contain slashes (e.g., `app/config/database`).

List endpoint returns only keys the caller has read permission for when auth is enabled.

## SSE Subscriptions

Subscribe to real-time key change events via Server-Sent Events:
- `/kv/subscribe/app/config` - exact key subscription
- `/kv/subscribe/app/*` or `/kv/subscribe/app/` - prefix subscription (all keys under app/)
- `/kv/subscribe/*` - all keys

Events are JSON: `{"key":"app/config","action":"update","timestamp":"2025-01-03T10:30:00Z"}`

Actions: `create`, `update`, `delete`

Go client example:
```go
sub, _ := client.Subscribe(ctx, "app/config")
for ev := range sub.Events() {
    log.Printf("%s: %s", ev.Action, ev.Key)
}
```

## Audit API (admin only)

```
POST   /audit/query              # query audit log (requires admin, JSON body with filters)
```

Audit logging is enabled with `--audit.enabled`. Tracks read, create, update, delete actions on /kv/* routes.
Query filters: key (prefix with `*`), actor, actor_type, action, result, from, to, limit.

## Web UI Routes

```
GET    /                              # main page with key list
GET    /web/keys                      # HTMX partial: key table (supports ?search=)
GET    /web/keys/new                  # HTMX partial: new key form
GET    /web/keys/view/{key...}        # HTMX partial: view modal
GET    /web/keys/edit/{key...}        # HTMX partial: edit form
GET    /web/keys/history/{key...}     # HTMX partial: history modal (requires git)
GET    /web/keys/revision/{key...}    # HTMX partial: revision view (requires git)
POST   /web/keys                      # create new key
PUT    /web/keys/{key...}             # update key value
DELETE /web/keys/{key...}             # delete key
POST   /web/keys/restore/{key...}     # restore key to revision (requires git)
POST   /web/theme                     # toggle theme (light/dark)
POST   /web/view-mode                 # toggle view mode (grid/cards)
POST   /web/sort                      # cycle sort order
POST   /web/secrets-filter            # cycle secrets filter (all/secrets/keys)
```

## Audit UI Routes (admin only, requires --audit.enabled)

```
GET    /audit                         # full audit log page with filters
GET    /web/audit                     # HTMX partial: audit table
```

Audit web handler in `app/server/web/audit.go`. Uses same page size as key list (`--server.page-size`).

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
- Auth hot-reload selectively invalidates sessions (only for users removed or with password changed), rejects invalid configs
- Auth hot-reload requires `--auth.hot-reload` flag to enable
- Web handlers check permissions server-side (not just UI conditions)
- Cache: optional loading cache wrapper, populated on reads, invalidated on writes
- Secrets: path-based detection (keys with "secrets" as path segment), NaCl secretbox + Argon2id
- Secrets permissions: explicit grant required (wildcards don't grant secrets), prefixPerm.grantsSecrets()
- Secrets API: returns 400 if secret path but --secrets.key not configured
- Secrets size: GetInfo returns encrypted storage size (larger than plaintext due to salt, nonce, auth tag)
- ZK encryption: client-side encryption, server stores opaque `$ZK$<base64>` blobs unchanged
- ZK detection: `stash.IsZKEncrypted()` from lib/stash, `ZKEncrypted` field in KeyInfo (db.go uses SUBSTR)
- ZK web UI: green shield icon, "Zero-Knowledge Encrypted" badge, edit disabled (server can't decrypt)
- ZK crypto: unified in `lib/stash/zk.go`, used by both server (detection) and client (encrypt/decrypt)
- Changelog: CHANGELOG.md (uppercase) in project root, update only on releases (no [Unreleased] placeholder)
- Keep it simple - no over-engineering

## E2E Testing

- **Location**: `e2e/e2e_test.go` with test data in `e2e/testdata/`
- **Technology**: playwright-go (Go bindings for Playwright, no npm/TypeScript)
- **Build tag**: `//go:build e2e` - excluded from regular `go test ./...`
- **Commands**:
  - `make e2e` - run headless
  - `make e2e-ui` - run with visible browser (slowMo enabled)
  - `make e2e-setup` - install chromium browser
- **Visible mode**: Set `E2E_HEADLESS=false` for visible browser

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

**ZK Encryption Indicators:**
- `.zk-lock-icon` - green shield icon in table/card row (svg)
- `.zk-badge` - "Zero-Knowledge Encrypted" badge in view modal
