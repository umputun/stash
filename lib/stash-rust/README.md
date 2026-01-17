# Stash Rust SDK

Rust client library for [Stash](https://github.com/umputun/stash) key-value configuration service.

## Features

- Idiomatic Rust API with async/await support
- Strong typing with Result-based error handling
- Zero-knowledge (ZK) encryption support (optional feature)
- Server-Sent Events (SSE) subscriptions for real-time updates
- Auto-reconnection with exponential backoff for subscriptions
- Cross-SDK compatibility for ZK encryption
- Clone + Send + Sync client for easy sharing across threads

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
stash = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

With zero-knowledge encryption support:

```toml
[dependencies]
stash = { version = "0.1", features = ["zk"] }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

## Quick Start

```rust
use stash::{Client, Format};

#[tokio::main]
async fn main() -> Result<(), stash::Error> {
    let client = Client::new("http://localhost:8080")?;

    // set a value
    client.set("app/config", "value", Some(Format::Text)).await?;

    // get a value
    let value = client.get("app/config").await?;
    println!("Value: {}", value);

    // list keys
    let keys = client.list(Some("app/")).await?;
    for key in keys {
        println!("Key: {}, Size: {} bytes", key.key, key.size);
    }

    Ok(())
}
```

## API Methods

### Client Creation

```rust
use stash::{Client, ClientOptions};
use std::time::Duration;

// simple creation with defaults
let client = Client::new("http://localhost:8080")?;

// with custom options
let client = Client::with_options("http://localhost:8080", ClientOptions {
    token: Some("my-api-token".into()),
    timeout: Some(Duration::from_secs(10)),
    zk_key: Some("my-secret-passphrase".into()),
})?;
```

### Key-Value Operations

```rust
// ping the server
client.ping().await?;

// get a value as string
let value = client.get("app/config").await?;

// get a value as bytes
let bytes = client.get_bytes("app/binary").await?;

// get with default fallback
let value = client.get_or_default("app/config", "default-value").await;

// get key metadata
let info = client.info("app/config").await?;
println!("Created: {}, Size: {}", info.created, info.size);

// set a value
client.set("app/config", "new-value", Some(Format::Json)).await?;

// set bytes
client.set_bytes("app/binary", &[1, 2, 3], None).await?;

// delete a key
client.delete("app/config").await?;

// list all keys
let all_keys = client.list(None).await?;

// list with prefix filter
let app_keys = client.list(Some("app/")).await?;
```

### Formats

The SDK supports format hints for syntax highlighting and display:

```rust
use stash::Format;

client.set("config.json", r#"{"key": "value"}"#, Some(Format::Json)).await?;
client.set("config.yaml", "key: value", Some(Format::Yaml)).await?;
client.set("config.toml", "key = \"value\"", Some(Format::Toml)).await?;
client.set("script.sh", "#!/bin/bash", Some(Format::Shell)).await?;
```

Available formats: `Text`, `Json`, `Yaml`, `Xml`, `Toml`, `Ini`, `Hcl`, `Shell`

### Real-time Subscriptions

Subscribe to key changes using Server-Sent Events (SSE):

```rust
use futures::StreamExt;

// subscribe to a specific key
let mut stream = client.subscribe("app/config").await?;
while let Some(event) = stream.next().await {
    let event = event?;
    println!("{}: {} at {}", event.action, event.key, event.timestamp);
}

// subscribe to all keys with a prefix
let mut stream = client.subscribe_prefix("app/").await?;
while let Some(event) = stream.next().await {
    let event = event?;
    println!("{}: {}", event.action, event.key);
}

// subscribe to all keys
let mut stream = client.subscribe_all().await?;
while let Some(event) = stream.next().await {
    let event = event?;
    println!("{}: {}", event.action, event.key);
}
```

Event actions: `create`, `update`, `delete`

Subscriptions automatically reconnect with exponential backoff (1s initial, 30s max) on connection failures.

## Zero-Knowledge Encryption

When the `zk` feature is enabled, the client supports transparent client-side encryption:

```rust
use stash::{Client, ClientOptions};

let client = Client::with_options("http://localhost:8080", ClientOptions {
    zk_key: Some("my-secret-passphrase-min-16-chars".into()),
    ..Default::default()
})?;

// values are automatically encrypted before sending to server
client.set("secrets/api-key", "sensitive-data", None).await?;

// and automatically decrypted when retrieved
let secret = client.get("secrets/api-key").await?;
assert_eq!(secret, "sensitive-data");
```

### ZK Encryption Details

- **Algorithm**: AES-256-GCM with Argon2id key derivation
- **Format**: `$ZK$<base64(salt[16] || nonce[12] || ciphertext || tag[16])>`
- **Passphrase**: Minimum 16 characters
- **Cross-SDK Compatible**: Values encrypted by Go, Python, TypeScript SDKs can be decrypted by Rust SDK and vice versa

Argon2id parameters (identical across all SDKs):
- Time cost: 1
- Memory cost: 65536 (64 MB)
- Parallelism: 4
- Output length: 32 bytes

### Manual ZK Operations

```rust
use stash::zk::{ZKCrypto, is_zk_encrypted};

// create ZK crypto instance
let zk = ZKCrypto::new("passphrase-min-16-chars")?;

// encrypt data
let encrypted = zk.encrypt(b"secret data")?;
println!("Encrypted: {}", encrypted);

// check if value is ZK-encrypted
assert!(is_zk_encrypted(&encrypted));

// decrypt data
let decrypted = zk.decrypt(&encrypted)?;
assert_eq!(decrypted, b"secret data");
```

## Error Handling

The SDK uses a Result-based error model with specific error types:

```rust
use stash::Error;

match client.get("missing-key").await {
    Ok(value) => println!("Got: {}", value),
    Err(Error::NotFound) => println!("Key not found"),
    Err(Error::Unauthorized) => println!("Invalid token"),
    Err(Error::Forbidden) => println!("Permission denied"),
    Err(Error::Decryption(msg)) => println!("Decryption failed: {}", msg),
    Err(Error::Connection(msg)) => println!("Connection error: {}", msg),
    Err(Error::Response { status, message }) => {
        println!("HTTP {}: {}", status, message);
    }
}
```

Error types:
- `NotFound` - Key does not exist (HTTP 404)
- `Unauthorized` - Authentication failed (HTTP 401)
- `Forbidden` - Access denied (HTTP 403)
- `Decryption(String)` - ZK decryption failed
- `Connection(String)` - Network or connection error
- `Response { status, message }` - Other HTTP errors

## Thread Safety

The `Client` is `Clone + Send + Sync`, making it safe to share across threads:

```rust
use std::sync::Arc;
use tokio::task;

let client = Arc::new(Client::new("http://localhost:8080")?);

let client1 = Arc::clone(&client);
let handle1 = task::spawn(async move {
    client1.set("key1", "value1", None).await
});

let client2 = Arc::clone(&client);
let handle2 = task::spawn(async move {
    client2.set("key2", "value2", None).await
});

handle1.await??;
handle2.await??;
```

## License

MIT
