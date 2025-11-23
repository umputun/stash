# Stash Project

Simple key-value configuration service - a minimal alternative to Consul KV or etcd.

## Project Structure

- **app/main.go** - Entry point with CLI options, logging, signal handling, wiring
- **app/main_test.go** - Integration tests
- **app/server/** - HTTP server with routegroup
  - `server.go` - Server struct, config, routes, graceful shutdown
  - `handlers.go` - HTTP handlers for KV API operations
  - `discovery.go` - HTTP handlers for service discovery API
  - `healthcheck.go` - Background health checker for TTL/HTTP checks
  - `web.go` - Web UI handlers, templates, static file serving
  - `auth.go` - Authentication: sessions, tokens, middleware, prefix-based ACL
  - `static/` - Embedded CSS, JS, HTMX library
  - `templates/` - Embedded HTML templates (base, index, login, services, partials)
  - `mocks/` - Generated mocks (moq)
- **app/store/** - Database storage layer (SQLite/PostgreSQL)
  - `store.go` - Types (KeyInfo, ServiceInstance, ServiceSummary), errors
  - `sqlite.go` - Unified Store with SQLite and PostgreSQL support

## Key Dependencies

- **CLI**: `github.com/umputun/go-flags`
- **Logging**: `github.com/go-pkgz/lgr`
- **HTTP**: `github.com/go-pkgz/routegroup`, `github.com/go-pkgz/rest`
- **Database**: `github.com/jmoiron/sqlx`, `modernc.org/sqlite`, `github.com/jackc/pgx/v5`
- **Testing**: `github.com/stretchr/testify`

## Build & Test

```bash
make build    # build binary
make test     # run tests
make lint     # run linter
make run      # run with logging enabled
```

## API

### Key-Value

```
GET    /kv/{key...}   # get value (returns raw body, 200/404)
PUT    /kv/{key...}   # set value (body is value, returns 200)
DELETE /kv/{key...}   # delete key (returns 204/404)
GET    /ping          # health check (returns "pong")
```

Keys can contain slashes (e.g., `app/config/database`).

### Service Discovery

```
PUT    /service/{name}               # register service instance
DELETE /service/{name}/{id}          # deregister service
PUT    /service/{name}/{id}/health   # send TTL heartbeat
GET    /service/{name}               # discover instances (?tag=, ?healthy=all)
GET    /services                     # list all services summary
```

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

### Services Web UI

```
GET    /web/services             # services page
GET    /web/services/list        # HTMX partial: services table
GET    /web/services/{name}      # HTMX partial: service instances
DELETE /web/services/{name}/{id} # deregister instance
```

## Auth Routes (when enabled)

```
GET    /login                    # login form
POST   /login                    # authenticate, set session cookie
POST   /logout                   # clear session, redirect to login
```

## Development Notes

- Consumer-side interfaces (KVStore defined in server package)
- Return concrete types, accept interfaces
- Database type auto-detected from URL (postgres:// vs file path)
- SQLite: WAL mode, SetMaxOpenConns(1), busy timeout, sync.RWMutex for locking
- PostgreSQL: standard connection pool, MVCC handles concurrency (no app-level locking)
- Query placeholders: SQLite uses `?`, PostgreSQL uses `$1, $2, ...` (adoptQuery converts)
- Keep it simple - no over-engineering
