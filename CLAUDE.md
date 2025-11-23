# Stash Project

Simple key-value configuration service - a minimal alternative to Consul KV or etcd.

## Project Structure

- **app/main.go** - Entry point with CLI options, logging, signal handling, wiring
- **app/main_test.go** - Integration tests
- **app/server/** - HTTP server with routegroup
  - `server.go` - Server struct, config, routes, graceful shutdown
  - `handlers.go` - HTTP handlers for KV operations
- **app/store/** - SQLite storage layer
  - `store.go` - Types and errors
  - `sqlite.go` - SQLite implementation with WAL mode

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
GET    /kv/{key}   # get value (returns raw body, 200/404)
PUT    /kv/{key}   # set value (body is value, returns 200)
DELETE /kv/{key}   # delete key (returns 204/404)
GET    /ping       # health check (returns "pong")
```

Keys can contain slashes (e.g., `app/config/database`).

## Development Notes

- Consumer-side interfaces (KVStore defined in server package)
- Return concrete types, accept interfaces
- SQLite with WAL mode, SetMaxOpenConns(1), busy timeout
- Keep it simple - no over-engineering
