# Stash Rust SDK

Rust client library for the Stash key-value configuration service.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
stash = { git = "https://github.com/umputun/stash" }
```

For zero-knowledge encryption support:

```toml
[dependencies]
stash = { git = "https://github.com/umputun/stash", features = ["zk"] }
```

To pin to a specific version:

```toml
[dependencies]
stash = { git = "https://github.com/umputun/stash", tag = "v1.0.0" }
```

## Quick Start

```rust
use stash::{Client, ClientOptions, Format};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // create client
    let client = Client::new("http://localhost:8080")?;

    // set a value
    client.set("app/config", "my-value", Some(Format::Text)).await?;

    // get a value
    let value = client.get("app/config").await?;
    println!("Value: {}", value);

    // list keys
    let keys = client.list(Some("app/")).await?;
    for key in keys {
        println!("Key: {}, Size: {}", key.key, key.size);
    }

    // delete a key
    client.delete("app/config").await?;

    Ok(())
}
```

## API Methods

### Key-Value Operations
- `ping()` - health check
- `get(key)` - get value as string
- `get_bytes(key)` - get value as bytes
- `get_or_default(key, default)` - get with fallback (returns default only for NotFound, propagates other errors)
- `info(key)` - get key metadata
- `history(key)` - get commit history (requires git versioning on server)
- `set(key, value, format)` - set value
- `set_bytes(key, value, format)` - set bytes
- `delete(key)` - delete key
- `list(prefix)` - list keys

### Subscriptions (SSE)
- `subscribe(key)` - subscribe to exact key changes
- `subscribe_prefix(prefix)` - subscribe to all keys with prefix
- `subscribe_all()` - subscribe to all key changes

## Authentication

```rust
use std::time::Duration;

let options = ClientOptions {
    token: Some("my-token".to_string()),
    timeout: Some(Duration::from_secs(10)),
    retries: Some(3), // retry transient errors with exponential backoff
    ..Default::default()
};

let client = Client::with_options("http://localhost:8080", options)?;
```

Retries use exponential backoff (starting at 1s) for transient failures like 5xx errors, timeouts, and connection errors. Default is 3 retries.

## Zero-Knowledge Encryption

Enable the `zk` feature and provide a passphrase to encrypt values client-side:

```rust
let options = ClientOptions {
    zk_key: Some("my-secret-passphrase-min-16-chars".to_string()),
    ..Default::default()
};

let client = Client::with_options("http://localhost:8080", options)?;

// values are automatically encrypted before sending to server
client.set("app/secret", "sensitive-data", None).await?;

// and decrypted when retrieved
let value = client.get("app/secret").await?;
```

The server stores opaque encrypted blobs (`$ZK$<base64>`). Only clients with the correct passphrase can decrypt values. ZK encryption is cross-compatible with Go, Python, TypeScript, and Java SDKs using the same passphrase.

## Subscriptions

Subscribe to real-time key change events using Server-Sent Events:

```rust
use futures::StreamExt;

// subscribe to a specific key
let mut stream = client.subscribe("app/config").await?;
while let Some(event) = stream.next().await {
    let event = event?;
    println!("{}: {} at {}", event.action, event.key, event.timestamp);
}

// subscribe to all keys with prefix
let mut stream = client.subscribe_prefix("app/").await?;
while let Some(event) = stream.next().await {
    let event = event?;
    println!("Change detected: {}", event.key);
}

// subscribe to all keys
let mut stream = client.subscribe_all().await?;
while let Some(event) = stream.next().await {
    let event = event?;
    match event.action.as_str() {
        "create" => println!("New key: {}", event.key),
        "update" => println!("Updated: {}", event.key),
        "delete" => println!("Deleted: {}", event.key),
        _ => {}
    }
}
```

Auto-reconnection with exponential backoff is built-in (1s initial delay, 30s max).

## Error Handling

```rust
use stash::Error;

match client.get("missing").await {
    Ok(value) => println!("Got: {}", value),
    Err(Error::NotFound) => println!("Key not found"),
    Err(Error::Unauthorized) => println!("Invalid token"),
    Err(e) => println!("Error: {}", e),
}
```

## License

MIT
