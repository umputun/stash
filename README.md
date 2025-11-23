# Stash

Simple key-value configuration service. A minimal alternative to Consul KV or etcd for storing and retrieving configuration data.

## Features

- HTTP API for key-value operations (GET, PUT, DELETE)
- SQLite-based persistent storage
- Hierarchical keys with slashes (e.g., `app/config/database`)
- Binary-safe values

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
| `--log.enabled` | `STASH_LOG_ENABLED` | `false` | Enable logging |
| `--log.debug` | `STASH_LOG_DEBUG` | `false` | Debug mode |

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
