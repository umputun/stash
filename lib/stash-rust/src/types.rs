use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Format for syntax highlighting and display
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    #[default]
    Text,
    Json,
    Yaml,
    Xml,
    Toml,
    Ini,
    Hcl,
    Shell,
}

impl Format {
    /// Convert format to string representation
    pub fn as_str(&self) -> &str {
        match self {
            Format::Text => "text",
            Format::Json => "json",
            Format::Yaml => "yaml",
            Format::Xml => "xml",
            Format::Toml => "toml",
            Format::Ini => "ini",
            Format::Hcl => "hcl",
            Format::Shell => "shell",
        }
    }
}

/// Metadata about a key in the store
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeyInfo {
    /// The key name
    pub key: String,

    /// Size in bytes
    pub size: i64,

    /// Format for syntax highlighting
    #[serde(default)]
    pub format: Format,

    /// Creation timestamp
    pub created: DateTime<Utc>,

    /// Last update timestamp
    pub updated: DateTime<Utc>,

    /// Whether this key contains a secret
    #[serde(default)]
    pub secret: bool,

    /// Whether this key is zero-knowledge encrypted
    #[serde(rename = "zkEncrypted", default)]
    pub zk_encrypted: bool,
}

/// Event from SSE subscription
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Event {
    /// The key that changed
    pub key: String,

    /// Action performed (create, update, delete)
    pub action: String,

    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
}
