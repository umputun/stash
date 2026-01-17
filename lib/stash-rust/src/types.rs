use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// format type for key values (used for syntax highlighting)
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

/// metadata information for a key
#[derive(Debug, Clone, Deserialize)]
pub struct KeyInfo {
    /// key name
    pub key: String,

    /// value size in bytes
    pub size: i64,

    /// format type
    pub format: Format,

    /// whether this key contains a secret
    pub secret: bool,

    /// whether this key is zero-knowledge encrypted
    #[serde(rename = "zkEncrypted")]
    pub zk_encrypted: bool,

    /// creation timestamp
    pub created: DateTime<Utc>,

    /// last update timestamp
    pub updated: DateTime<Utc>,
}

/// subscription event for key changes
#[derive(Debug, Clone, Deserialize)]
pub struct Event {
    /// key that changed
    pub key: String,

    /// action performed: create, update, or delete
    pub action: String,

    /// timestamp of the event
    pub timestamp: DateTime<Utc>,
}
