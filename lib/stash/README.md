# Stash Go Client

Go client library for the [Stash](https://github.com/umputun/stash) key-value configuration service.

## Installation

```bash
go get github.com/umputun/stash/lib/stash
```

## Usage

### Basic Usage

```go
package main

import (
    "context"
    "log"

    "github.com/umputun/stash/lib/stash"
)

func main() {
    // create client with just the base URL
    client, err := stash.New("http://localhost:8080")
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // store a value with format
    err = client.SetWithFormat(ctx, "app/config", `{"debug": true}`, stash.FormatJSON)
    if err != nil {
        log.Fatal(err)
    }

    // retrieve a value
    value, err := client.Get(ctx, "app/config")
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("value: %s", value)

    // list all keys
    keys, err := client.List(ctx, "")
    if err != nil {
        log.Fatal(err)
    }
    for _, k := range keys {
        log.Printf("key: %s, size: %d, format: %s", k.Key, k.Size, k.Format)
    }

    // delete a key
    err = client.Delete(ctx, "app/config")
    if err != nil {
        log.Fatal(err)
    }
}
```

### With Authentication

```go
client, err := stash.New("http://localhost:8080",
    stash.WithToken("your-api-token"),
)
```

### With Custom Options

```go
client, err := stash.New("http://localhost:8080",
    stash.WithToken("your-api-token"),
    stash.WithTimeout(10*time.Second),      // default: 30s
    stash.WithRetry(5, 200*time.Millisecond), // default: 3 retries, 100ms delay
)
```

### With Custom HTTP Client

```go
httpClient := &http.Client{
    Transport: &http.Transport{
        MaxIdleConns: 10,
    },
}

client, err := stash.New("http://localhost:8080",
    stash.WithHTTPClient(httpClient),
)
```

### With Zero-Knowledge Encryption

Client-side encryption where the server never sees plaintext values:

```go
client, err := stash.New("http://localhost:8080",
    stash.WithZKKey("your-secret-passphrase"), // min 16 characters
)

// values are encrypted before sending to server
err = client.Set(ctx, "app/credentials", `{"api_key": "secret123"}`)

// values are decrypted automatically when retrieved
value, err := client.Get(ctx, "app/credentials")
// value = `{"api_key": "secret123"}`
```

The server stores encrypted blobs with `$ZK$` prefix. Without the passphrase, values cannot be decrypted. The web UI shows a lock icon for ZK-encrypted keys and disables editing.

**Algorithm**: AES-256-GCM with Argon2id key derivation.

## API

### Constructor

```go
func New(baseURL string, opts ...Option) (*Client, error)
```

Creates a new Stash client. The base URL is required; all other options are optional.

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `WithToken(token)` | Set Bearer token for authentication | none |
| `WithTimeout(duration)` | HTTP request timeout | 30s |
| `WithRetry(count, delay)` | Retry configuration | 3 retries, 100ms |
| `WithHTTPClient(client)` | Custom http.Client | default client |
| `WithZKKey(passphrase)` | Enable client-side ZK encryption (min 16 chars) | none |

### Methods

#### Get

```go
func (c *Client) Get(ctx context.Context, key string) (string, error)
```

Retrieves a value by key as a string. Returns `ErrNotFound` if the key doesn't exist.

#### GetOrDefault

```go
func (c *Client) GetOrDefault(ctx context.Context, key string, defaultValue string) (string, error)
```

Retrieves a value by key, returning `defaultValue` if the key doesn't exist. Other errors are still returned.

#### GetBytes

```go
func (c *Client) GetBytes(ctx context.Context, key string) ([]byte, error)
```

Retrieves a value by key as raw bytes. Use this for binary data.

#### Set

```go
func (c *Client) Set(ctx context.Context, key string, value string) error
```

Stores a value with default text format.

#### SetWithFormat

```go
func (c *Client) SetWithFormat(ctx context.Context, key string, value string, format Format) error
```

Stores a value with explicit format. Available formats: `FormatText`, `FormatJSON`, `FormatYAML`, `FormatXML`, `FormatTOML`, `FormatINI`, `FormatHCL`, `FormatShell`.

#### Delete

```go
func (c *Client) Delete(ctx context.Context, key string) error
```

Removes a key. Returns `ErrNotFound` if the key doesn't exist.

#### List

```go
func (c *Client) List(ctx context.Context, prefix string) ([]KeyInfo, error)
```

Returns all keys, optionally filtered by prefix. Pass empty string to list all keys.

#### Info

```go
func (c *Client) Info(ctx context.Context, key string) (KeyInfo, error)
```

Retrieves metadata for a specific key. Returns `ErrNotFound` if the key doesn't exist.

#### Ping

```go
func (c *Client) Ping(ctx context.Context) error
```

Checks server connectivity.

### Types

```go
type KeyInfo struct {
    Key         string
    Size        int
    Format      string
    Secret      bool      // true if key is in a secrets path
    ZKEncrypted bool      // true if value is ZK-encrypted
    CreatedAt   time.Time
    UpdatedAt   time.Time
}
```

### Errors

```go
var (
    ErrNotFound     = errors.New("key not found")
    ErrUnauthorized = errors.New("unauthorized")
    ErrForbidden    = errors.New("forbidden")
)

// ResponseError wraps HTTP errors with status code
type ResponseError struct {
    StatusCode int
}
```

Use `errors.Is` to check for sentinel errors:

```go
value, err := client.Get(ctx, "missing-key")
if errors.Is(err, stash.ErrNotFound) {
    // handle not found
}
```

## License

MIT License - see [LICENSE](../../LICENSE) for details.
