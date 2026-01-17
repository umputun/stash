use stash::{Client, ClientOptions, Format};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Stash Rust SDK Basic Example ===\n");

    // create a simple client
    let client = Client::new("http://localhost:8080")?;

    // health check
    println!("1. Ping server...");
    client.ping().await?;
    println!("   Server is up!\n");

    // set a key with format
    println!("2. Setting key 'example/config' with YAML format...");
    let yaml_value = r#"
database:
  host: localhost
  port: 5432
logging:
  level: info
"#;
    client
        .set("example/config", yaml_value, Some(Format::Yaml))
        .await?;
    println!("   Key set successfully\n");

    // get the key back
    println!("3. Getting key 'example/config'...");
    let value = client.get("example/config").await?;
    println!("   Value:\n{}\n", value);

    // get key info
    println!("4. Getting metadata for 'example/config'...");
    let info = client.info("example/config").await?;
    println!("   Key: {}", info.key);
    println!("   Size: {} bytes", info.size);
    println!("   Format: {:?}", info.format);
    println!("   Created: {}", info.created_at);
    println!("   Updated: {}\n", info.updated_at);

    // set another key with bytes
    println!("5. Setting binary data...");
    let binary_data = vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]; // "Hello" in bytes
    client
        .set_bytes("example/binary", &binary_data, Some(Format::Text))
        .await?;
    println!("   Binary key set\n");

    // get with default
    println!("6. Getting with default (existing key)...");
    let value = client
        .get_or_default("example/config", "default-value")
        .await?;
    println!("   Got: {} chars\n", value.len());

    println!("7. Getting with default (non-existing key)...");
    let value = client
        .get_or_default("example/missing", "default-value")
        .await?;
    println!("   Got default: {}\n", value);

    // list keys
    println!("8. Listing all keys with prefix 'example/'...");
    let keys = client.list(Some("example/")).await?;
    println!("   Found {} keys:", keys.len());
    for key in keys {
        println!("     - {} ({:?}, {} bytes)", key.key, key.format, key.size);
    }
    println!();

    // delete keys
    println!("9. Cleaning up - deleting keys...");
    client.delete("example/config").await?;
    client.delete("example/binary").await?;
    println!("   Keys deleted\n");

    // demonstrate authentication with options
    println!("10. Creating client with options (token, timeout, retries)...");
    let options = ClientOptions {
        token: Some("my-api-token".to_string()),
        timeout: Some(Duration::from_secs(10)),
        retries: Some(3),
        zk_key: None,
    };
    let _auth_client = Client::with_options("http://localhost:8080", options)?;
    println!("   Client created with custom options\n");

    println!("=== Example completed successfully ===");

    Ok(())
}
