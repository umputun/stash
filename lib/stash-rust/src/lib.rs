//! Rust client library for Stash key-value configuration service
//!
//! # Example
//!
//! ```no_run
//! use stash::{Client, Format};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), stash::Error> {
//!     let client = Client::new("http://localhost:8080")?;
//!
//!     // set a value
//!     client.set("app/config", "value", Some(Format::Text)).await?;
//!
//!     // get a value
//!     let value = client.get("app/config").await?;
//!     println!("Value: {}", value);
//!
//!     Ok(())
//! }
//! ```

mod client;
mod error;
mod types;

pub use client::{Client, ClientOptions};
pub use error::Error;
pub use types::{Event, Format, KeyInfo};
