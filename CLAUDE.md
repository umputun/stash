# Stash Project

Simple key-value configuration service - a minimal alternative to Consul KV or etcd.

## Project Structure

- **app/main.go** - Entry point with CLI options, logging, signal handling, wiring
- **app/main_test.go** - Integration tests
- **app/server/** - HTTP server with routegroup
  - `server.go` - Server struct, config, routes, graceful shutdown
  - `handlers.go` - HTTP handlers for KV API operations
  - `web.go` - Web UI handlers, templates, static file serving
  - `auth.go` - Authentication: sessions, tokens, middleware, prefix-based ACL
  - `static/` - Embedded CSS, JS, HTMX library
  - `templates/` - Embedded HTML templates (base, index, login, partials)
  - `mocks/` - Generated mocks (moq)
- **app/store/** - SQLite storage layer
  - `store.go` - Types (KeyInfo), errors
  - `sqlite.go` - SQLite implementation with WAL mode, List() method

## Key Dependencies

- **CLI**: `github.com/umputun/go-flags`
- **Logging**: `github.com/go-pkgz/lgr`
- **HTTP**: `github.com/go-pkgz/routegroup`, `github.com/go-pkgz/rest`
- **Database**: `github.com/jmoiron/sqlx`, `modernc.org/sqlite`
- **Testing**: `github.com/stretchr/testify`

## Build & Test

```bash
make build    # build binary
make test     # run tests
make lint     # run linter
make run      # run with logging enabled
```

## API

```
GET    /kv/{key...}   # get value (returns raw body, 200/404)
PUT    /kv/{key...}   # set value (body is value, returns 200)
DELETE /kv/{key...}   # delete key (returns 204/404)
GET    /ping          # health check (returns "pong")
```

Keys can contain slashes (e.g., `app/config/database`).

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

## Development Notes

- Consumer-side interfaces (KVStore defined in server package)
- Return concrete types, accept interfaces
- SQLite with WAL mode, SetMaxOpenConns(1), busy timeout
- Keep it simple - no over-engineering
