# Stash Rust SDK

Rust client library for [Stash](https://github.com/umputun/stash) key-value configuration service.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
stash = "0.1"
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

## License

MIT
