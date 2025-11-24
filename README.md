# Stash

Lightweight key-value configuration service for centralized config management. Store application settings, feature flags, and shared configuration with a simple HTTP API and web UI. A minimal alternative to Consul KV or etcd for microservices and containerized applications that need a straightforward way to manage configuration without complex infrastructure. Not a secrets vault - see [Security Note](#security-note).

## Features

- HTTP API for key-value operations (GET, PUT, DELETE)
- Web UI for managing keys (view, create, edit, delete)
- SQLite or PostgreSQL storage (auto-detected from URL)
- Hierarchical keys with slashes (e.g., `app/config/database`)
- Binary-safe values
- Light/dark theme with system preference detection
- Optional authentication with password login and API tokens
- Prefix-based access control for API tokens (read/write permissions)

## Security Note

Stash stores values in plaintext and is designed for application configuration, not secrets management. For sensitive credentials, consider:

- [HashiCorp Vault](https://www.vaultproject.io/) or similar secrets managers
- Client-side encryption before storing values in Stash
- Filesystem-level encryption (LUKS, FileVault) for the database file

## Installation

### From GitHub Releases

Download the latest release for your platform from the [releases page](https://github.com/umputun/stash/releases/latest).

### Homebrew (macOS)

```bash
brew install umputun/apps/stash
```

### Debian/Ubuntu (deb package)

```bash
wget https://github.com/umputun/stash/releases/latest/download/stash_<version>_linux_amd64.deb
sudo dpkg -i stash_<version>_linux_amd64.deb
```

### RHEL/CentOS/Fedora (rpm package)

```bash
wget https://github.com/umputun/stash/releases/latest/download/stash_<version>_linux_amd64.rpm
sudo rpm -i stash_<version>_linux_amd64.rpm
```

### Docker

```bash
docker pull ghcr.io/umputun/stash:latest
```

### Build from source

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
| `--server.read-timeout` | `STASH_SERVER_READ_TIMEOUT` | `5s` | Read timeout (duration format) |
| `--auth.password-hash` | `STASH_AUTH_PASSWORD_HASH` | - | bcrypt hash for admin password (enables auth) |
| `--auth.token` | `STASH_AUTH_AUTH_TOKEN` | - | API token with prefix permissions (repeatable) |
| `--auth.login-ttl` | `STASH_AUTH_LOGIN_TTL` | `24h` | Login session TTL (duration format) |
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
