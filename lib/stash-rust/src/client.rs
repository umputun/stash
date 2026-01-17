use crate::error::Error;
use crate::types::{Format, KeyInfo};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use std::time::Duration;

/// configuration options for stash client
#[derive(Default, Clone)]
pub struct ClientOptions {
    /// authentication token for API access
    pub token: Option<String>,

    /// request timeout (default: 30s)
    pub timeout: Option<Duration>,

    /// number of retry attempts on transient failures (default: 3)
    pub retries: Option<u32>,

    /// passphrase for zero-knowledge encryption (min 16 chars)
    pub zk_key: Option<String>,
}

/// stash http client for key-value operations
#[derive(Clone)]
pub struct Client {
    http_client: reqwest::Client,
    base_url: String,
    #[allow(dead_code)] // will be used in iteration 2 for zk encryption
    options: ClientOptions,
}

impl Client {
    /// creates a new client with default options
    pub fn new(base_url: &str) -> Result<Self, Error> {
        Self::with_options(base_url, ClientOptions::default())
    }

    /// creates a new client with custom options
    pub fn with_options(base_url: &str, options: ClientOptions) -> Result<Self, Error> {
        // validate zk_key length if provided
        if let Some(ref key) = options.zk_key {
            if key.len() < 16 {
                return Err(Error::InvalidParameter(
                    "zk_key must be at least 16 characters".to_string(),
                ));
            }
        }

        let timeout = options.timeout.unwrap_or(Duration::from_secs(30));

        let mut headers = HeaderMap::new();
        if let Some(ref token) = options.token {
            let mut auth_value = HeaderValue::from_str(&format!("Bearer {}", token))
                .map_err(|e| Error::InvalidParameter(format!("invalid token: {}", e)))?;
            auth_value.set_sensitive(true);
            headers.insert(AUTHORIZATION, auth_value);
        }

        let http_client = reqwest::Client::builder()
            .timeout(timeout)
            .default_headers(headers)
            .build()
            .map_err(|e| Error::Connection(e.to_string()))?;

        Ok(Client {
            http_client,
            base_url: base_url.trim_end_matches('/').to_string(),
            options,
        })
    }

    /// health check endpoint
    pub async fn ping(&self) -> Result<(), Error> {
        let url = format!("{}/ping", self.base_url);
        let resp = self.http_client.get(&url).send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Error::Response {
                status: resp.status().as_u16(),
                message: resp.text().await.unwrap_or_default(),
            })
        }
    }

    /// retrieves a key's value as a string
    pub async fn get(&self, key: &str) -> Result<String, Error> {
        let bytes = self.get_bytes(key).await?;
        String::from_utf8(bytes).map_err(|e| Error::Connection(format!("invalid UTF-8: {}", e)))
    }

    /// retrieves a key's value as raw bytes
    pub async fn get_bytes(&self, key: &str) -> Result<Vec<u8>, Error> {
        let key_encoded = urlencoding::encode(key);
        let url = format!("{}/kv/{}", self.base_url, key_encoded);
        let resp = self.http_client.get(&url).send().await?;

        if resp.status().is_success() {
            Ok(resp.bytes().await?.to_vec())
        } else {
            Err(resp.error_for_status().unwrap_err().into())
        }
    }

    /// retrieves a key's value, returning default if key not found
    pub async fn get_or_default(&self, key: &str, default: &str) -> String {
        self.get(key).await.unwrap_or_else(|_| default.to_string())
    }

    /// retrieves metadata for a key
    pub async fn info(&self, key: &str) -> Result<KeyInfo, Error> {
        // use prefix filtering for efficiency (matches go sdk behavior)
        let keys = self.list(Some(key)).await?;
        keys.into_iter()
            .find(|k| k.key == key)
            .ok_or(Error::NotFound)
    }

    /// stores a key-value pair
    pub async fn set(&self, key: &str, value: &str, format: Option<Format>) -> Result<(), Error> {
        self.set_bytes(key, value.as_bytes(), format).await
    }

    /// stores a key with raw bytes value
    pub async fn set_bytes(
        &self,
        key: &str,
        value: &[u8],
        format: Option<Format>,
    ) -> Result<(), Error> {
        let key_encoded = urlencoding::encode(key);
        let mut url = format!("{}/kv/{}", self.base_url, key_encoded);

        if let Some(fmt) = format {
            let format_str = match fmt {
                Format::Text => "text",
                Format::Json => "json",
                Format::Yaml => "yaml",
                Format::Xml => "xml",
                Format::Toml => "toml",
                Format::Ini => "ini",
                Format::Hcl => "hcl",
                Format::Shell => "shell",
            };
            url = format!("{}?format={}", url, format_str);
        }

        let resp = self
            .http_client
            .put(&url)
            .body(value.to_vec())
            .send()
            .await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(resp.error_for_status().unwrap_err().into())
        }
    }

    /// deletes a key
    pub async fn delete(&self, key: &str) -> Result<(), Error> {
        let key_encoded = urlencoding::encode(key);
        let url = format!("{}/kv/{}", self.base_url, key_encoded);
        let resp = self.http_client.delete(&url).send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(resp.error_for_status().unwrap_err().into())
        }
    }

    /// lists all keys, optionally filtered by prefix
    pub async fn list(&self, prefix: Option<&str>) -> Result<Vec<KeyInfo>, Error> {
        let mut url = format!("{}/kv/", self.base_url);

        if let Some(pfx) = prefix {
            let pfx_encoded = urlencoding::encode(pfx);
            url = format!("{}?prefix={}", url, pfx_encoded);
        }

        let resp = self.http_client.get(&url).send().await?;

        if resp.status().is_success() {
            let keys: Vec<KeyInfo> = resp.json().await?;
            Ok(keys)
        } else {
            Err(resp.error_for_status().unwrap_err().into())
        }
    }
}
