//! Rust client library for Stash key-value configuration service.
//!
//! This library provides a simple HTTP client for interacting with a Stash server,
//! supporting all core KV operations, zero-knowledge encryption, and SSE subscriptions.

mod client;
mod error;
mod types;

pub use client::{Client, ClientOptions};
pub use error::Error;
pub use types::{Event, Format, KeyInfo};
