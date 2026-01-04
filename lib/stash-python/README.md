# Stash Python Client

Python client library for [Stash](https://github.com/umputun/stash) - a simple key-value configuration service.

## Installation

```bash
pip install stash-client
```

Or with uv:

```bash
uv add stash-client
```

For local development:

```bash
cd lib/stash-python
uv sync --all-extras
```

## Quick Start

```python
from stash import Client

# basic usage
client = Client("http://localhost:8080")
client.set("app/config", '{"debug": true}', fmt="json")
value = client.get("app/config")
print(value)  # {"debug": true}

# with authentication
client = Client("http://localhost:8080", token="your-api-token")

# with zero-knowledge encryption
client = Client(
    "http://localhost:8080",
    zk_key="your-secret-passphrase-min-16-chars"
)
# values are encrypted client-side before sending to server
client.set("secrets/api-key", "sk-secret-value")
# automatically decrypted on retrieval
value = client.get("secrets/api-key")  # "sk-secret-value"
```

## Context Manager

```python
from stash import Client

with Client("http://localhost:8080", zk_key="passphrase-min-16") as client:
    client.set("key", "value")
    value = client.get("key")
# passphrase is cleared from memory on exit
```

## Dict-like Access

```python
client = Client("http://localhost:8080")

# set
client["app/config"] = "value"

# get
value = client["app/config"]

# delete
del client["app/config"]

# check existence
if "app/config" in client:
    print("exists")
```

## API Reference

### Client

```python
Client(
    base_url: str,
    token: str | None = None,
    timeout: float = 30.0,
    retries: int = 3,
    zk_key: str | None = None
)
```

**Parameters:**
- `base_url`: Stash server URL
- `token`: Bearer token for authentication
- `timeout`: Request timeout in seconds
- `retries`: Number of retry attempts for failed requests
- `zk_key`: Passphrase for zero-knowledge encryption (min 16 chars)

### Methods

| Method | Description |
|--------|-------------|
| `get(key: str) -> str` | Get value as string |
| `get_bytes(key: str) -> bytes` | Get value as bytes |
| `get_or_default(key: str, default: str) -> str` | Get value or return default |
| `set(key: str, value: str, fmt: str = "text")` | Set value with format |
| `delete(key: str)` | Delete key |
| `list(prefix: str = "") -> list[KeyInfo]` | List keys with optional prefix filter |
| `info(key: str) -> KeyInfo` | Get key metadata |
| `ping() -> None` | Check server connectivity |
| `close() -> None` | Clear ZK passphrase from memory |
| `subscribe(key: str) -> Subscription` | Subscribe to exact key changes |
| `subscribe_prefix(prefix: str) -> Subscription` | Subscribe to prefix changes |
| `subscribe_all() -> Subscription` | Subscribe to all key changes |

### Subscriptions

Real-time key change notifications via Server-Sent Events:

```python
from stash import Client

client = Client("http://localhost:8080", token="your-token")

# subscribe to exact key
with client.subscribe("app/config") as sub:
    for event in sub:
        print(f"{event.action}: {event.key} at {event.timestamp}")

# subscribe to prefix (all keys under app/)
with client.subscribe_prefix("app") as sub:
    for event in sub:
        print(f"{event.action}: {event.key}")

# subscribe to all keys
with client.subscribe_all() as sub:
    for event in sub:
        print(f"{event.action}: {event.key}")
```

**SubscriptionEvent:**
- `key`: The key that changed
- `action`: `create`, `update`, or `delete`
- `timestamp`: RFC3339 timestamp

Subscriptions automatically reconnect on connection failure with exponential backoff (1s initial, 30s max).

### KeyInfo

```python
@dataclass
class KeyInfo:
    key: str
    size: int
    format: str
    secret: bool
    zk_encrypted: bool
    created_at: datetime
    updated_at: datetime
```

### Errors

```python
from stash import (
    StashError,       # base exception
    NotFoundError,    # key not found (404)
    UnauthorizedError, # unauthorized (401)
    ForbiddenError,   # forbidden (403)
    DecryptionError,  # ZK decryption failed
    ConnectionError,  # connection failed
)
```

## Zero-Knowledge Encryption

When `zk_key` is provided, all values are encrypted client-side using AES-256-GCM with Argon2id key derivation. The server only stores encrypted data and cannot decrypt it.

Encryption parameters (compatible with Go client):
- Algorithm: AES-256-GCM
- Key derivation: Argon2id (time=1, memory=64MB, parallelism=4)
- Encrypted format: `$ZK$<base64(salt || nonce || ciphertext || tag)>`

## Development

```bash
# install dev dependencies
uv sync --all-extras

# run tests
uv run pytest

# run tests with coverage
uv run pytest --cov

# run linter
uv run ruff check .

# format code
uv run ruff format .
```

## License

MIT License - see the main [Stash repository](https://github.com/umputun/stash) for details.
