# Stash

Simple key-value configuration service. A minimal alternative to Consul KV or etcd for storing and retrieving configuration data.

## Features

- HTTP API for key-value operations (GET, PUT, DELETE)
- Web UI for managing keys (view, create, edit, delete)
- SQLite-based persistent storage
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
stash --store=/path/to/stash.db --server.address=:8484 --log.enabled
```

### Command Line Options

| Option | Environment | Default | Description |
|--------|-------------|---------|-------------|
| `-s, --store` | `STASH_STORE` | `stash.db` | Path to SQLite database file |
| `--server.address` | `STASH_SERVER_ADDRESS` | `:8484` | Server listen address |
| `--server.read-timeout` | `STASH_SERVER_READ_TIMEOUT` | `5` | Read timeout in seconds |
| `--auth.password-hash` | `STASH_AUTH_PASSWORD_HASH` | - | bcrypt hash for admin password (enables auth) |
| `--auth.token` | `STASH_AUTH_AUTH_TOKEN` | - | API token with prefix permissions (repeatable) |
| `--auth.login-ttl` | `STASH_AUTH_LOGIN_TTL` | `1440` | Login session TTL in minutes |
| `--dbg` | `DEBUG` | `false` | Debug mode |

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

```bash
docker run -p 8484:8484 -v /data:/srv/data ghcr.io/umputun/stash \
    --store=/srv/data/stash.db --log.enabled
```

## License

MIT License - see [LICENSE](LICENSE) for details.
