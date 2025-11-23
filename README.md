# Stash

Simple key-value configuration service. A minimal alternative to Consul KV or etcd for storing and retrieving configuration data.

## Features

- HTTP API for key-value operations (GET, PUT, DELETE)
- Service discovery with TTL and HTTP health checks
- Web UI for managing keys and viewing services
- SQLite or PostgreSQL storage (auto-detected from URL)
- Hierarchical keys with slashes (e.g., `app/config/database`)
- Binary-safe values
- Light/dark theme with system preference detection
- Optional authentication with password login and API tokens
- Prefix-based access control for API tokens (read/write permissions)

## Installation

```bash
go install github.com/umputun/stash@latest
```

Or build from source:

```bash
make build
```

## Usage

```bash
# SQLite (default)
stash --db=/path/to/stash.db --server.address=:8484

# PostgreSQL
stash --db="postgres://user:pass@localhost:5432/stash?sslmode=disable"
```

### Command Line Options

| Option | Environment | Default | Description |
|--------|-------------|---------|-------------|
| `-d, --db` | `STASH_DB` | `stash.db` | Database URL (SQLite file or postgres://...) |
| `--server.address` | `STASH_SERVER_ADDRESS` | `:8484` | Server listen address |
| `--server.read-timeout` | `STASH_SERVER_READ_TIMEOUT` | `5` | Read timeout in seconds |
| `--auth.password-hash` | `STASH_AUTH_PASSWORD_HASH` | - | bcrypt hash for admin password (enables auth) |
| `--auth.token` | `STASH_AUTH_AUTH_TOKEN` | - | API token with prefix permissions (repeatable) |
| `--auth.login-ttl` | `STASH_AUTH_LOGIN_TTL` | `1440` | Login session TTL in minutes |
| `--discovery.ttl-check-interval` | `STASH_DISCOVERY_TTL_CHECK_INTERVAL` | `5` | TTL expiration check interval in seconds |
| `--discovery.http-check-interval` | `STASH_DISCOVERY_HTTP_CHECK_INTERVAL` | `10` | HTTP health check interval in seconds |
| `--discovery.http-check-timeout` | `STASH_DISCOVERY_HTTP_CHECK_TIMEOUT` | `5` | HTTP health check timeout in seconds |
| `--dbg` | `DEBUG` | `false` | Debug mode |

### Database URLs

| Database | URL Format |
|----------|------------|
| SQLite (file) | `stash.db`, `./data/stash.db`, `file:stash.db` |
| SQLite (memory) | `:memory:` |
| PostgreSQL | `postgres://user:pass@host:5432/dbname?sslmode=disable` |

## Authentication

Authentication is optional. When `--auth.password-hash` is set, all routes (except `/ping` and `/static/`) require authentication.

### Enabling Authentication

Generate a bcrypt hash for your password:

```bash
htpasswd -nbBC 10 "" "your-password" | tr -d ':\n' | sed 's/$2y/$2a/'
```

Start with authentication enabled:

```bash
stash --auth.password-hash '$2a$10$...'
```

### Access Methods

| Method | Usage | Scope |
|--------|-------|-------|
| Web UI | Password login form | Full access |
| API | Bearer token | Prefix-scoped |

### API Tokens

Define API tokens with prefix-based permissions using `--auth.token`:

```bash
# format: token:prefix:permissions
# permissions: r (read), w (write), rw (read-write)

stash --auth.password-hash '$2a$10$...' \
      --auth.token "admin-api:*:rw" \
      --auth.token "app1-svc:app1/*:rw" \
      --auth.token "monitoring:*:r"
```

Use tokens via Bearer authentication:

```bash
# full access token
curl -H "Authorization: Bearer admin-api" http://localhost:8484/kv/any/key

# scoped token - can read/write only app1/* keys
curl -H "Authorization: Bearer app1-svc" -X PUT -d 'value' http://localhost:8484/kv/app1/config

# read-only token
curl -H "Authorization: Bearer monitoring" http://localhost:8484/kv/app1/config
```

### Prefix Matching

- `*` matches all keys
- `app/*` matches keys starting with `app/`
- `app/config` matches exact key only

When multiple prefixes match, the longest (most specific) wins.

## API

### Get value

```bash
curl http://localhost:8484/kv/mykey
```

Returns the raw value with status 200, or 404 if key not found.

### Set value

```bash
curl -X PUT -d 'my value' http://localhost:8484/kv/mykey
```

Body contains the raw value. Returns 200 on success.

### Delete key

```bash
curl -X DELETE http://localhost:8484/kv/mykey
```

Returns 204 on success, or 404 if key not found.

### Health check

```bash
curl http://localhost:8484/ping
```

Returns `pong` with status 200.

## Service Discovery

Stash provides simple service discovery similar to Consul. Services register themselves, send heartbeats (TTL) or respond to HTTP health checks, and clients can discover healthy instances.

### Register a service

```bash
# TTL-based health check (service sends heartbeats)
curl -X PUT -H "Content-Type: application/json" \
  -d '{"address":"10.0.0.5","port":8080,"tags":["primary"],"check":{"type":"ttl","ttl":30}}' \
  http://localhost:8484/service/api
# Response: {"id":"svc-abc123"}

# HTTP-based health check (stash polls the endpoint)
curl -X PUT -H "Content-Type: application/json" \
  -d '{"address":"10.0.0.5","port":8080,"check":{"type":"http","url":"http://10.0.0.5:8080/health","interval":10}}' \
  http://localhost:8484/service/api
```

### Send heartbeat (TTL)

```bash
curl -X PUT http://localhost:8484/service/api/svc-abc123/health
```

### Discover services

```bash
# Get all healthy instances
curl http://localhost:8484/service/api

# Filter by tags
curl "http://localhost:8484/service/api?tag=primary"

# Include unhealthy instances
curl "http://localhost:8484/service/api?healthy=all"
```

### List all services

```bash
curl http://localhost:8484/services
# Response: [{"name":"api","instances":3,"healthy":2},{"name":"db","instances":1,"healthy":1}]
```

### Deregister a service

```bash
curl -X DELETE http://localhost:8484/service/api/svc-abc123
```

## Web UI

Access the web interface at `http://localhost:8484/`. Features:

- Table view of all keys with size and timestamps
- Search keys by name
- View, create, edit, and delete keys
- Binary value display (base64 encoded)
- Light/dark theme toggle

## Examples

```bash
# set a simple value
curl -X PUT -d 'production' http://localhost:8484/kv/app/env

# set JSON configuration
curl -X PUT -d '{"host":"db.example.com","port":5432}' http://localhost:8484/kv/app/config/database

# get the value
curl http://localhost:8484/kv/app/config/database

# delete a key
curl -X DELETE http://localhost:8484/kv/app/env
```

## Docker

### SQLite

```bash
docker run -p 8484:8484 -v /data:/srv/data ghcr.io/umputun/stash \
    --db=/srv/data/stash.db
```

### PostgreSQL with Docker Compose

```yaml
version: '3.8'
services:
  stash:
    image: ghcr.io/umputun/stash
    environment:
      - STASH_DB=postgres://stash:secret@postgres:5432/stash?sslmode=disable
    depends_on:
      - postgres
    ports:
      - "8484:8484"

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=stash
      - POSTGRES_PASSWORD=secret
      - POSTGRES_DB=stash
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

## License

MIT License - see [LICENSE](LICENSE) for details.
