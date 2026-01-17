//! Basic example demonstrating common Stash client operations

use futures::StreamExt;
use stash::{Client, ClientOptions, Error, Format};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // create a simple client
    let client = Client::new("http://localhost:8080")?;

    // or create with options
    let _client_with_opts = Client::with_options(
        "http://localhost:8080",
        ClientOptions {
            token: Some("my-api-token".to_string()),
            timeout: Some(Duration::from_secs(10)),
            ..Default::default()
        },
    )?;

    // ping the server
    println!("Pinging server...");
    client.ping().await?;
    println!("Server is alive!");

    // set some values with different formats
    println!("\nSetting values...");
    client
        .set("app/config/name", "MyApp", Some(Format::Text))
        .await?;
    client
        .set(
            "app/config/settings",
            r#"{"debug": true, "port": 8080}"#,
            Some(Format::Json),
        )
        .await?;
    client
        .set(
            "app/config/database",
            "host: localhost\nport: 5432",
            Some(Format::Yaml),
        )
        .await?;

    // get values
    println!("\nGetting values...");
    let name = client.get("app/config/name").await?;
    println!("App name: {}", name);

    let settings = client.get("app/config/settings").await?;
    println!("Settings: {}", settings);

    // get with default fallback
    let missing = client.get_or_default("app/missing", "default-value").await;
    println!("Missing key (with default): {}", missing);

    // get key metadata
    println!("\nGetting key info...");
    let info = client.info("app/config/name").await?;
    println!(
        "Key: {}, Size: {} bytes, Created: {}, Format: {:?}",
        info.key, info.size, info.created, info.format
    );

    // list all keys with a prefix
    println!("\nListing keys with prefix 'app/config/'...");
    let keys = client.list(Some("app/config/")).await?;
    for key in &keys {
        println!(
            "  - {} ({} bytes, format: {:?})",
            key.key, key.size, key.format
        );
    }

    // subscribe to key changes
    println!("\nSubscribing to prefix 'app/config/'...");
    println!("(This will run indefinitely - press Ctrl+C to stop)");
    println!("Try modifying keys with prefix 'app/config/' in another terminal\n");

    let mut stream = client.subscribe_prefix("app/config/").await?;

    // set a value to trigger an event
    tokio::spawn({
        let client = client.clone();
        async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let _ = client
                .set("app/config/triggered", "event-value", None)
                .await;
        }
    });

    // process events (this runs forever with auto-reconnection)
    let mut count = 0;
    while let Some(event) = stream.next().await {
        match event {
            Ok(ev) => {
                println!("[{}] key={} at {}", ev.action, ev.key, ev.timestamp);
                count += 1;
                // exit after seeing a few events (for demo purposes)
                if count >= 1 {
                    println!("\nSeen {} event(s), exiting demo", count);
                    break;
                }
            }
            Err(e) => {
                eprintln!("Error in event stream: {}", e);
                // stream will auto-reconnect, continue processing
            }
        }
    }

    // cleanup: delete the keys we created
    println!("\nCleaning up...");
    let _ = client.delete("app/config/name").await;
    let _ = client.delete("app/config/settings").await;
    let _ = client.delete("app/config/database").await;
    let _ = client.delete("app/config/triggered").await;

    println!("Done!");
    Ok(())
}
