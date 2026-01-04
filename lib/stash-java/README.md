# Stash Java Client

Java client library for [Stash](https://github.com/umputun/stash) - a simple key-value configuration service.

## Features

- Simple, fluent API with builder pattern
- Zero-knowledge encryption (AES-256-GCM + Argon2id)
- Cross-compatible with Go, Python, and TypeScript SDKs
- Automatic retry with exponential backoff
- Java 11+ support

## Installation

**Gradle:**

```kotlin
dependencies {
    implementation("io.github.umputun:stash-client:0.1.0")
}
```

**Maven:**

```xml
<dependency>
    <groupId>io.github.umputun</groupId>
    <artifactId>stash-client</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

### Basic Operations

```java
import io.github.umputun.stash.Client;
import io.github.umputun.stash.Format;

try (Client client = Client.builder("http://localhost:8080").build()) {
    // store a value
    client.set("app/config", "{\"debug\": true}", Format.JSON);

    // retrieve a value
    String value = client.get("app/config");

    // get with default
    String val = client.getOrDefault("missing/key", "fallback");

    // delete
    client.delete("app/config");

    // list keys
    List<KeyInfo> keys = client.list("app/");

    // health check
    boolean healthy = client.ping();
}
```

### With Authentication

```java
Client client = Client.builder("http://localhost:8080")
    .token("your-api-token")
    .build();
```

### With Zero-Knowledge Encryption

Values are automatically encrypted before sending and decrypted after receiving:

```java
Client client = Client.builder("http://localhost:8080")
    .zkKey("your-passphrase-min-16-bytes")
    .build();

// value is encrypted client-side before sending
client.set("secrets/api-key", "super-secret-value");

// value is decrypted client-side after receiving
String secret = client.get("secrets/api-key");
```

### Configuration Options

```java
Client client = Client.builder("http://localhost:8080")
    .token("api-token")                    // authentication token
    .timeout(Duration.ofSeconds(60))       // request timeout (default: 30s)
    .retries(5)                            // retry attempts (default: 3)
    .retryDelay(Duration.ofMillis(200))    // base retry delay (default: 100ms)
    .zkKey("encryption-passphrase")        // ZK encryption passphrase
    .build();
```

## API Reference

### Client Methods

| Method | Description |
|--------|-------------|
| `get(key)` | Get value as string |
| `getBytes(key)` | Get value as byte array |
| `getOrDefault(key, default)` | Get value or return default if not found |
| `set(key, value)` | Store value with TEXT format |
| `set(key, value, format)` | Store value with specified format |
| `delete(key)` | Delete a key |
| `list()` | List all keys |
| `list(prefix)` | List keys with prefix filter |
| `info(key)` | Get metadata for a key |
| `ping()` | Check server health |
| `subscribe(key)` | Subscribe to exact key changes |
| `subscribePrefix(prefix)` | Subscribe to prefix changes |
| `subscribeAll()` | Subscribe to all key changes |

### Formats

- `Format.TEXT` - plain text (default)
- `Format.JSON` - JSON
- `Format.YAML` - YAML
- `Format.XML` - XML
- `Format.TOML` - TOML
- `Format.INI` - INI
- `Format.HCL` - HashiCorp HCL
- `Format.SHELL` - Shell script

### Exceptions

| Exception | HTTP Status | Description |
|-----------|-------------|-------------|
| `NotFoundError` | 404 | Key does not exist |
| `UnauthorizedError` | 401 | Missing or invalid token |
| `ForbiddenError` | 403 | Access denied |
| `DecryptionError` | - | ZK decryption failed |
| `ConnectionError` | - | Network error |
| `StashException` | - | Base exception |

### Subscriptions

Real-time key change notifications via Server-Sent Events:

```java
import io.github.umputun.stash.Client;
import io.github.umputun.stash.Subscription;
import io.github.umputun.stash.SubscriptionEvent;

Client client = Client.builder("http://localhost:8080")
    .token("your-token")
    .build();

// subscribe to exact key
try (Subscription sub = client.subscribe("app/config")) {
    for (SubscriptionEvent event : sub) {
        System.out.printf("%s: %s at %s%n",
            event.getAction(), event.getKey(), event.getTimestamp());
    }
}

// subscribe to prefix (all keys under app/)
try (Subscription sub = client.subscribePrefix("app")) {
    for (SubscriptionEvent event : sub) {
        System.out.printf("%s: %s%n", event.getAction(), event.getKey());
    }
}

// subscribe to all keys
try (Subscription sub = client.subscribeAll()) {
    for (SubscriptionEvent event : sub) {
        System.out.printf("%s: %s%n", event.getAction(), event.getKey());
    }
}
```

**SubscriptionEvent:**
- `getKey()` - The key that changed
- `getAction()` - The action: `create`, `update`, or `delete`
- `getTimestamp()` - RFC3339 timestamp

Subscriptions automatically reconnect on connection failure with exponential backoff (1s initial, 30s max).

## Zero-Knowledge Encryption

ZK encryption ensures the server never sees plaintext values. The encryption uses:

- **AES-256-GCM** for symmetric encryption
- **Argon2id** for key derivation (64MB memory, 1 iteration, 4 parallelism)

Encrypted values are stored as `$ZK$<base64>` and are fully compatible with Go, Python, and TypeScript Stash clients.

## License

MIT
