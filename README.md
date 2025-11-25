# Stash [![Build Status](https://github.com/umputun/stash/workflows/build/badge.svg)](https://github.com/umputun/stash/actions) [![Coverage Status](https://coveralls.io/repos/github/umputun/stash/badge.svg?branch=master)](https://coveralls.io/github/umputun/stash?branch=master)

Lightweight key-value configuration service for centralized config management. Store application settings, feature flags, and shared configuration with a simple HTTP API and web UI. A minimal alternative to Consul KV or etcd for microservices and containerized applications that need a straightforward way to manage configuration without complex infrastructure. Not a secrets vault - see [Security Note](#security-note).

## Features

- HTTP API for key-value operations (GET, PUT, DELETE)
- Web UI for managing keys (view, create, edit, delete)
- SQLite or PostgreSQL storage (auto-detected from URL)
- Hierarchical keys with slashes (e.g., `app/config/database`)
- Binary-safe values
- Light/dark theme with system preference detection
- Optional authentication with username/password login and API tokens
- Prefix-based access control for both users and API tokens (read/write permissions)
- Optional git versioning with full audit trail and point-in-time recovery

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

Stash uses subcommands: `server` for running the service and `restore` for recovering data from git history.

```bash
# SQLite (default)
stash server --db=/path/to/stash.db --server.address=:8080

# PostgreSQL
stash server --db="postgres://user:pass@localhost:5432/stash?sslmode=disable"

# With git versioning enabled
stash server --git.enabled --git.path=/data/.history

# Restore from git revision
stash restore --rev=abc1234 --db=/path/to/stash.db --git.path=/data/.history
```

### Server Options

| Option | Environment | Default | Description |
|--------|-------------|---------|-------------|
| `-d, --db` | `STASH_DB` | `stash.db` | Database URL (SQLite file or postgres://...) |
| `--server.address` | `STASH_SERVER_ADDRESS` | `:8080` | Server listen address |
| `--server.read-timeout` | `STASH_SERVER_READ_TIMEOUT` | `5s` | Read timeout (duration format) |
| `--server.base-url` | `STASH_SERVER_BASE_URL` | - | Base URL path for reverse proxy (e.g., `/stash`) |
| `--auth.file` | `STASH_AUTH_FILE` | - | Path to auth config file (enables auth) |
| `--auth.login-ttl` | `STASH_AUTH_LOGIN_TTL` | `24h` | Login session TTL (duration format) |
| `--git.enabled` | `STASH_GIT_ENABLED` | `false` | Enable git versioning |
| `--git.path` | `STASH_GIT_PATH` | `.history` | Git repository path |
| `--git.branch` | `STASH_GIT_BRANCH` | `master` | Git branch name |
| `--git.remote` | `STASH_GIT_REMOTE` | - | Git remote name (for push) |
| `--git.push` | `STASH_GIT_PUSH` | `false` | Auto-push after commits |
| `--dbg` | `DEBUG` | `false` | Debug mode |

### Restore Options

| Option | Environment | Default | Description |
|--------|-------------|---------|-------------|
| `--rev` | - | (required) | Git revision to restore (commit hash, tag, or branch) |
| `-d, --db` | `STASH_DB` | `stash.db` | Database URL |
| `--git.path` | `STASH_GIT_PATH` | `.history` | Git repository path |
| `--git.branch` | `STASH_GIT_BRANCH` | `master` | Git branch name |
| `--git.remote` | `STASH_GIT_REMOTE` | - | Git remote name (pulls before restore if set) |
| `--dbg` | `DEBUG` | `false` | Debug mode |

### Database URLs

| Database | URL Format |
|----------|------------|
| SQLite (file) | `stash.db`, `./data/stash.db`, `file:stash.db` |
| SQLite (memory) | `:memory:` |
| PostgreSQL | `postgres://user:pass@host:5432/dbname?sslmode=disable` |

### Subpath Deployment

To serve stash at a subpath (e.g., `example.com/stash`), use `--server.base-url`:

```bash
stash --server.base-url=/stash
```

The base URL must start with `/` and have no trailing slash. All routes, URLs, and cookies will be prefixed accordingly.

When using a reverse proxy, forward requests with the path intact (do not strip the prefix). Example reproxy configuration:

```yaml
labels:
  - reproxy.server=example.com
  - reproxy.route=^/stash/
  - reproxy.port=8080
```

## Authentication

Authentication is optional. When `--auth.file` is set, all routes (except `/ping` and `/static/`) require authentication.

### Auth Config File

Create a YAML config file (e.g., `stash-auth.yml`) with users and/or API tokens. See [`stash-auth-example.yml`](stash-auth-example.yml) for a complete example with comments.

```yaml
users:
  - name: admin
    password: "$2a$10$..."  # bcrypt hash
    permissions:
      - prefix: "*"
        access: rw
  - name: readonly
    password: "$2a$10$..."
    permissions:
      - prefix: "*"
        access: r

tokens:
  - token: "a4f8d9e2-7c3b-4a1f-9e2d-8c7b6a5f4e3d"
    permissions:
      - prefix: "app1/*"
        access: rw
  - token: "b7e4c2a1-9d8f-4e3b-8a2c-1f7e6d5c4b3a"
    permissions:
      - prefix: "*"
        access: r
```

Start with authentication enabled:

```bash
stash server --auth.file=/path/to/stash-auth.yml
```

**Security**: The auth config file contains password hashes and API tokens. Set restrictive file permissions:

```bash
chmod 600 stash-auth.yml
```

### Generating Password Hashes

```bash
htpasswd -nbBC 10 "" "your-password" | tr -d ':\n' | sed 's/$2y/$2a/'
```

### Access Methods

| Method | Usage | Scope |
|--------|-------|-------|
| Web UI | Username + password login | Prefix-scoped per user |
| API | Bearer token | Prefix-scoped per token |

### Users (Web UI)

Users authenticate via the web login form with username and password. Each user has prefix-based permissions that control which keys they can read/write.

### API Tokens

Generate secure random tokens (use UUID or similar):

```bash
uuidgen  # macOS/Linux
openssl rand -hex 16  # alternative
```

Use tokens via Bearer authentication:

```bash
curl -H "Authorization: Bearer a4f8d9e2-7c3b-4a1f-9e2d-8c7b6a5f4e3d" \
     http://localhost:8080/kv/app1/config
```

**Warning**: Do not use simple names like "admin" or "monitoring" as tokens - they are easy to guess.

### Prefix Matching

- `*` matches all keys
- `app/*` matches keys starting with `app/`
- `app/config` matches exact key only

When multiple prefixes match, the longest (most specific) wins.

### Permission Levels

- `r` or `read` - read-only access
- `w` or `write` - write-only access
- `rw` or `readwrite` - full read-write access

## Git Versioning

Optional git versioning tracks all key changes in a local git repository. Every set or delete operation creates a git commit, providing a full audit trail and point-in-time recovery.

### Enabling Git Versioning

```bash
stash server --git.enabled --git.path=/data/.history
```

### Storage Format

Keys are stored as files with `.val` extension. The key path maps directly to the file path:

| Key | File Path |
|-----|-----------|
| `app/config/db` | `.history/app/config/db.val` |
| `app/config/redis` | `.history/app/config/redis.val` |
| `service/timeout` | `.history/service/timeout.val` |

Directory structure example:

```
.history/
├── app/
│   └── config/
│       ├── db.val       # key: app/config/db
│       └── redis.val    # key: app/config/redis
└── service/
    └── timeout.val      # key: service/timeout
```

### Remote Sync

Enable auto-push to a remote repository for backup:

```bash
# initialize git repo with remote first
cd /data/.history
git init
git remote add origin git@github.com:user/config-backup.git

# run with auto-push
stash server --git.enabled --git.path=/data/.history --git.remote=origin --git.push
```

When remote changes exist (someone else pushed), stash will attempt to pull before pushing. If there's a merge conflict, the local commit is preserved and a warning is logged with manual resolution instructions.

**Note**: For local bare repositories on the same machine, use absolute paths (e.g., `/data/backup.git`). Relative paths like `../backup.git` are not supported by the underlying git library.

### Restore from History

Recover the database to any point in git history:

```bash
# list available commits
cd /data/.history && git log --oneline

# restore to specific revision
stash restore --rev=abc1234 --db=/data/stash.db --git.path=/data/.history
```

The restore command:
1. Pulls from remote if configured
2. Checks out the specified revision
3. Clears all keys from the database
4. Restores all keys from the git repository

## API

### Get value

```bash
curl http://localhost:8080/kv/mykey
```

Returns the raw value with status 200, or 404 if key not found.

### Set value

```bash
curl -X PUT -d 'my value' http://localhost:8080/kv/mykey
```

Body contains the raw value. Returns 200 on success.

### Delete key

```bash
curl -X DELETE http://localhost:8080/kv/mykey
```

Returns 204 on success, or 404 if key not found.

### Health check

```bash
curl http://localhost:8080/ping
```

Returns `pong` with status 200.

## Web UI

Access the web interface at `http://localhost:8080/`. Features:

- Table view of all keys with size and timestamps
- Search keys by name
- View, create, edit, and delete keys
- Binary value display (base64 encoded)
- Light/dark theme toggle

## Examples

```bash
# set a simple value
curl -X PUT -d 'production' http://localhost:8080/kv/app/env

# set JSON configuration
curl -X PUT -d '{"host":"db.example.com","port":5432}' http://localhost:8080/kv/app/config/database

# get the value
curl http://localhost:8080/kv/app/config/database

# delete a key
curl -X DELETE http://localhost:8080/kv/app/env
```

## Docker

### SQLite

```bash
docker run -p 8080:8080 -v /data:/srv/data ghcr.io/umputun/stash \
    server --db=/srv/data/stash.db
```

### With Git Versioning

```bash
docker run -p 8080:8080 -v /data:/srv/data ghcr.io/umputun/stash \
    server --db=/srv/data/stash.db --git.enabled --git.path=/srv/data/.history
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
      - "8080:8080"

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

### Production Setup with SSL

See [`docker-compose-example.yml`](docker-compose-example.yml) for a complete production setup with:
- [Reproxy](https://github.com/umputun/reproxy) reverse proxy with automatic SSL (Let's Encrypt)
- PostgreSQL database
- Authentication enabled

```bash
# copy and customize the example
cp docker-compose-example.yml docker-compose.yml

# set your domain in SSL_ACME_FQDN and reproxy.server label
# create auth config file with users and tokens
cat > stash-auth.yml << 'EOF'
users:
  - name: admin
    password: "$2a$10$..."  # generate with htpasswd
    permissions:
      - prefix: "*"
        access: rw
EOF

# set auth file path in .env
echo 'STASH_AUTH_FILE=/srv/data/stash-auth.yml' > .env

# start services
docker-compose up -d
```

## Notes

- **Concurrency**: Stash uses last-write-wins semantics with no conflict detection. Concurrent updates to the same key will silently overwrite.

## License

MIT License - see [LICENSE](LICENSE) for details.
