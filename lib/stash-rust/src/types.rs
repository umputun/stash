use chrono::{DateTime, Utc};
use serde::{de, Deserialize, Deserializer, Serialize};

/// base64 deserializer for binary values in JSON responses
mod base64_bytes {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(s) if !s.is_empty() => STANDARD
                .decode(&s)
                .map_err(|e| de::Error::custom(format!("base64 decode: {}", e))),
            _ => Ok(Vec::new()),
        }
    }
}

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
    /// fallback for unknown/future format values from server
    #[serde(other)]
    Unknown,
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
    pub zk_encrypted: bool,

    /// creation timestamp
    pub created_at: DateTime<Utc>,

    /// last update timestamp
    pub updated_at: DateTime<Utc>,
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

/// history entry representing a single revision of a key
#[derive(Debug, Clone, Deserialize)]
pub struct HistoryEntry {
    /// git commit hash
    pub hash: String,

    /// timestamp of the revision
    pub timestamp: DateTime<Utc>,

    /// author of the change
    pub author: String,

    /// operation performed: set or delete
    pub operation: String,

    /// format of the value
    pub format: String,

    /// value at this revision (base64 decoded from JSON)
    #[serde(deserialize_with = "base64_bytes::deserialize")]
    pub value: Vec<u8>,
}
