# Stash Rust SDK

Rust client library for the Stash key-value configuration service.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
stash = "0.1"
```

For zero-knowledge encryption support:

```toml
[dependencies]
stash = { version = "0.1", features = ["zk"] }
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

- `ping()` - health check
- `get(key)` - get value as string
- `get_bytes(key)` - get value as bytes
- `get_or_default(key, default)` - get with fallback
- `info(key)` - get key metadata
- `set(key, value, format)` - set value
- `set_bytes(key, value, format)` - set bytes
- `delete(key)` - delete key
- `list(prefix)` - list keys

## Authentication

```rust
use std::time::Duration;

let options = ClientOptions {
    token: Some("my-token".to_string()),
    timeout: Some(Duration::from_secs(10)),
    ..Default::default()
};

let client = Client::with_options("http://localhost:8080", options)?;
```

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
