use crate::error::Error;
use crate::types::{Event, Format, HistoryEntry, KeyInfo};
use futures::stream::{Stream, StreamExt};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest_eventsource::{Event as SseEvent, EventSource};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest_retry::{policies::ExponentialBackoff, RetryTransientMiddleware};
use std::pin::Pin;
use std::time::Duration;

#[cfg(feature = "zk")]
use crate::zk::ZKCrypto;

/// encodes key path segments while preserving slashes for hierarchical keys.
/// handles special cases: dot segments (., ..) are encoded to prevent URL normalization.
/// e.g., "app/config?special=true" -> "app/config%3Fspecial%3Dtrue"
/// e.g., "app/../secret" -> "app/%2E%2E/secret"
fn encode_key_path(key: &str) -> String {
    key.split('/')
        .map(|segment| {
            // encode dot segments explicitly to prevent URL parser normalization
            if segment == "." || segment == ".." {
                segment.replace('.', "%2E")
            } else {
                urlencoding::encode(segment).into_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// configuration options for stash client
#[derive(Default, Clone)]
pub struct ClientOptions {
    /// authentication token for API access
    pub token: Option<String>,

    /// request timeout (default: 30s)
    pub timeout: Option<Duration>,

    /// number of retry attempts for transient failures (default: 3)
    /// retries use exponential backoff starting at 1s
    pub retries: Option<u32>,

    /// passphrase for zero-knowledge encryption (min 16 chars)
    pub zk_key: Option<String>,
}

/// stash http client for key-value operations
#[derive(Clone)]
pub struct Client {
    http_client: ClientWithMiddleware,
    sse_client: reqwest::Client, // for SSE subscriptions (no timeout)
    base_url: String,
    #[cfg(feature = "zk")]
    zk_crypto: Option<ZKCrypto>,
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
        let retries = options.retries.unwrap_or(3);

        let mut headers = HeaderMap::new();
        if let Some(ref token) = options.token {
            let mut auth_value = HeaderValue::from_str(&format!("Bearer {}", token))
                .map_err(|e| Error::InvalidParameter(format!("invalid token: {}", e)))?;
            auth_value.set_sensitive(true);
            headers.insert(AUTHORIZATION, auth_value);
        }

        let raw_client = reqwest::Client::builder()
            .timeout(timeout)
            .default_headers(headers.clone())
            .build()
            .map_err(|e| Error::Connection(e.to_string()))?;

        // build middleware client with retry support
        let retry_policy = ExponentialBackoff::builder().build_with_max_retries(retries);
        let http_client = ClientBuilder::new(raw_client)
            .with(RetryTransientMiddleware::new_with_policy(retry_policy))
            .build();

        // SSE client: connect timeout but no request timeout (streams are long-lived)
        let sse_client = reqwest::Client::builder()
            .connect_timeout(timeout)
            .default_headers(headers)
            .build()
            .map_err(|e| Error::Connection(e.to_string()))?;

        #[cfg(feature = "zk")]
        let zk_crypto = if let Some(ref key) = options.zk_key {
            Some(ZKCrypto::new(key)?)
        } else {
            None
        };

        Ok(Client {
            http_client,
            sse_client,
            base_url: base_url.trim_end_matches('/').to_string(),
            #[cfg(feature = "zk")]
            zk_crypto,
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
        let url = format!("{}/kv/{}", self.base_url, encode_key_path(key));
        let resp = self.http_client.get(&url).send().await?;

        if !resp.status().is_success() {
            return Err(resp.error_for_status().unwrap_err().into());
        }

        let data = resp.bytes().await?.to_vec();

        // decrypt if zk is enabled and data is encrypted
        #[cfg(feature = "zk")]
        if let Some(ref zk) = self.zk_crypto {
            if let Ok(value_str) = std::str::from_utf8(&data) {
                if crate::zk::is_zk_encrypted(value_str) {
                    return zk.decrypt(value_str);
                }
            }
        }

        Ok(data)
    }

    /// retrieves a key's value, returning default if key not found
    ///
    /// only returns default for NotFound errors; other errors are propagated
    pub async fn get_or_default(&self, key: &str, default: &str) -> Result<String, Error> {
        match self.get(key).await {
            Ok(v) => Ok(v),
            Err(Error::NotFound) => Ok(default.to_string()),
            Err(e) => Err(e),
        }
    }

    /// retrieves metadata for a key
    pub async fn info(&self, key: &str) -> Result<KeyInfo, Error> {
        // use prefix filtering for efficiency (matches go sdk behavior)
        let keys = self.list(Some(key)).await?;
        keys.into_iter()
            .find(|k| k.key == key)
            .ok_or(Error::NotFound)
    }

    /// retrieves the commit history for a key
    ///
    /// requires git versioning to be enabled on the server
    pub async fn history(&self, key: &str) -> Result<Vec<HistoryEntry>, Error> {
        let url = format!("{}/kv/history/{}", self.base_url, encode_key_path(key));
        let resp = self.http_client.get(&url).send().await?;

        if resp.status().is_success() {
            let entries: Vec<HistoryEntry> = resp.json().await?;
            Ok(entries)
        } else {
            Err(resp.error_for_status().unwrap_err().into())
        }
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
        let mut url = format!("{}/kv/{}", self.base_url, encode_key_path(key));

        if let Some(fmt) = format {
            let format_str = match fmt {
                Format::Text | Format::Unknown => "text",
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

        // encrypt if zk is enabled
        #[cfg(feature = "zk")]
        let body = if let Some(ref zk) = self.zk_crypto {
            zk.encrypt(value)?.into_bytes()
        } else {
            value.to_vec()
        };

        #[cfg(not(feature = "zk"))]
        let body = value.to_vec();

        let resp = self.http_client.put(&url).body(body).send().await?;

        if resp.status().is_success() {
            Ok(())
        } else {
            Err(resp.error_for_status().unwrap_err().into())
        }
    }

    /// deletes a key
    pub async fn delete(&self, key: &str) -> Result<(), Error> {
        let url = format!("{}/kv/{}", self.base_url, encode_key_path(key));
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

    /// subscribes to changes for a specific key
    ///
    /// returns a stream of events for the key
    pub async fn subscribe(
        &self,
        key: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>, Error> {
        if key.is_empty() {
            return Err(Error::InvalidParameter("key is required".to_string()));
        }
        self.create_subscription(key).await
    }

    /// subscribes to changes for all keys with a given prefix
    ///
    /// returns a stream of events for all keys matching the prefix
    pub async fn subscribe_prefix(
        &self,
        prefix: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>, Error> {
        if prefix.is_empty() {
            return Err(Error::InvalidParameter("prefix is required".to_string()));
        }
        // append /* for wildcard subscription
        let path = format!("{}/*", prefix);
        self.create_subscription(&path).await
    }

    /// subscribes to changes for all keys
    ///
    /// returns a stream of events for all keys in the store
    pub async fn subscribe_all(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>, Error> {
        self.create_subscription("*").await
    }

    /// creates an SSE subscription stream for the given path
    ///
    /// note: auto-reconnection with exponential backoff is built into reqwest-eventsource
    /// (1s initial delay, 2x backoff factor, 30s max delay)
    async fn create_subscription(
        &self,
        path: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>, Error> {
        let url = format!("{}/kv/subscribe/{}", self.base_url, encode_key_path(path));

        // use SSE client without timeout (streams are long-lived)
        let request_builder = self.sse_client.get(&url);

        let event_source =
            EventSource::new(request_builder).map_err(|e| Error::Connection(e.to_string()))?;

        let stream = event_source.filter_map(|result| async move {
            match result {
                Ok(SseEvent::Open) => None, // filter out connection open events
                Ok(SseEvent::Message(msg)) => {
                    if msg.event == "change" {
                        Some(
                            serde_json::from_str::<Event>(&msg.data)
                                .map_err(|e| Error::Connection(format!("parse event: {}", e))),
                        )
                    } else {
                        None // filter out other event types
                    }
                }
                Err(e) => Some(Err(Error::Connection(e.to_string()))),
            }
        });

        Ok(Box::pin(stream))
    }
}
