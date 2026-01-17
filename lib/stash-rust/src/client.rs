use crate::error::Error;
use crate::types::{Event, Format, KeyInfo};
use futures::stream::{Stream, StreamExt};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use std::pin::Pin;
use std::time::Duration;
use tokio::time::sleep;

#[cfg(feature = "zk")]
use crate::zk::{is_zk_encrypted, ZKCrypto};

/// Options for configuring the Stash client
#[derive(Default, Clone)]
pub struct ClientOptions {
    /// API token for authentication
    pub token: Option<String>,

    /// Request timeout (default: 30 seconds)
    pub timeout: Option<Duration>,

    /// Zero-knowledge encryption passphrase (min 16 characters)
    pub zk_key: Option<String>,
}

/// Stash client for key-value operations
#[derive(Clone)]
pub struct Client {
    http_client: reqwest::Client,
    base_url: String,
    options: ClientOptions,
}

impl Client {
    /// Create a new client with default options
    pub fn new(base_url: &str) -> Result<Self, Error> {
        Self::with_options(base_url, ClientOptions::default())
    }

    /// Create a new client with custom options
    pub fn with_options(base_url: &str, options: ClientOptions) -> Result<Self, Error> {
        if base_url.is_empty() {
            return Err(Error::Connection("base URL is required".to_string()));
        }

        // validate zk_key if provided
        if let Some(ref key) = options.zk_key {
            if key.len() < 16 {
                return Err(Error::Connection(
                    "zk_key must be at least 16 characters".to_string(),
                ));
            }
        }

        let mut headers = HeaderMap::new();
        if let Some(ref token) = options.token {
            let header_value = HeaderValue::from_str(&format!("Bearer {}", token))
                .map_err(|e| Error::Connection(format!("invalid token: {}", e)))?;
            headers.insert(AUTHORIZATION, header_value);
        }

        let timeout = options.timeout.unwrap_or(Duration::from_secs(30));

        let http_client = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            .build()
            .map_err(|e| Error::Connection(format!("failed to create HTTP client: {}", e)))?;

        Ok(Self {
            http_client,
            base_url: base_url.trim_end_matches('/').to_string(),
            options,
        })
    }

    /// Ping the server to check connectivity
    pub async fn ping(&self) -> Result<(), Error> {
        let url = format!("{}/ping", self.base_url);
        let response = self.http_client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::from(response.error_for_status().unwrap_err()))
        }
    }

    /// Get a value as a string
    pub async fn get(&self, key: &str) -> Result<String, Error> {
        let bytes = self.get_bytes(key).await?;
        String::from_utf8(bytes)
            .map_err(|e| Error::Connection(format!("invalid UTF-8 in response: {}", e)))
    }

    /// Get a value as bytes
    pub async fn get_bytes(&self, key: &str) -> Result<Vec<u8>, Error> {
        if key.is_empty() {
            return Err(Error::Connection("key cannot be empty".to_string()));
        }
        let url = format!("{}/kv/{}", self.base_url, key);
        let response = self.http_client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(Error::from(response.error_for_status().unwrap_err()));
        }

        let bytes = response.bytes().await?.to_vec();

        // decrypt if ZK-encrypted and zk_key is set
        #[cfg(feature = "zk")]
        if let Some(ref zk_key) = self.options.zk_key {
            let value_str = String::from_utf8_lossy(&bytes);
            if is_zk_encrypted(&value_str) {
                let zk = ZKCrypto::new(zk_key)?;
                return zk.decrypt(&value_str);
            }
        }

        Ok(bytes)
    }

    /// Get a value or return a default if the key doesn't exist
    pub async fn get_or_default(&self, key: &str, default: &str) -> String {
        match self.get(key).await {
            Ok(value) => value,
            Err(_) => default.to_string(),
        }
    }

    /// Get metadata about a key
    pub async fn info(&self, key: &str) -> Result<KeyInfo, Error> {
        if key.is_empty() {
            return Err(Error::Connection("key cannot be empty".to_string()));
        }
        let keys = self.list(Some(key)).await?;
        keys.into_iter()
            .find(|k| k.key == key)
            .ok_or(Error::NotFound)
    }

    /// Set a value
    pub async fn set(&self, key: &str, value: &str, format: Option<Format>) -> Result<(), Error> {
        self.set_bytes(key, value.as_bytes(), format).await
    }

    /// Set a value from bytes
    pub async fn set_bytes(
        &self,
        key: &str,
        value: &[u8],
        format: Option<Format>,
    ) -> Result<(), Error> {
        if key.is_empty() {
            return Err(Error::Connection("key cannot be empty".to_string()));
        }
        let url = format!("{}/kv/{}", self.base_url, key);

        // encrypt if zk_key is set
        let body = {
            #[cfg(feature = "zk")]
            if let Some(ref zk_key) = self.options.zk_key {
                let zk = ZKCrypto::new(zk_key)?;
                zk.encrypt(value)?.into_bytes()
            } else {
                value.to_vec()
            }

            #[cfg(not(feature = "zk"))]
            value.to_vec()
        };

        let mut request = self
            .http_client
            .put(&url)
            .header(CONTENT_TYPE, "application/octet-stream");

        if let Some(fmt) = format {
            request = request.query(&[("format", fmt.as_str())]);
        }

        let response = request.body(body).send().await?;

        if !response.status().is_success() {
            return Err(Error::from(response.error_for_status().unwrap_err()));
        }

        Ok(())
    }

    /// Delete a key
    pub async fn delete(&self, key: &str) -> Result<(), Error> {
        if key.is_empty() {
            return Err(Error::Connection("key cannot be empty".to_string()));
        }
        let url = format!("{}/kv/{}", self.base_url, key);
        let response = self.http_client.delete(&url).send().await?;

        if !response.status().is_success() {
            return Err(Error::from(response.error_for_status().unwrap_err()));
        }

        Ok(())
    }

    /// List all keys, optionally filtered by prefix
    pub async fn list(&self, prefix: Option<&str>) -> Result<Vec<KeyInfo>, Error> {
        let url = format!("{}/kv/", self.base_url);

        let mut request = self.http_client.get(&url);
        if let Some(p) = prefix {
            request = request.query(&[("prefix", p)]);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            return Err(Error::from(response.error_for_status().unwrap_err()));
        }

        let keys: Vec<KeyInfo> = response.json().await?;
        Ok(keys)
    }

    /// Subscribe to changes for a specific key
    pub async fn subscribe(
        &self,
        key: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>, Error> {
        if key.is_empty() {
            return Err(Error::Connection("key cannot be empty".to_string()));
        }
        let url = format!("{}/kv/subscribe/{}", self.base_url, key);
        self.create_sse_stream(&url).await
    }

    /// Subscribe to changes for all keys with a given prefix
    pub async fn subscribe_prefix(
        &self,
        prefix: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>, Error> {
        if prefix.is_empty() {
            return Err(Error::Connection("prefix cannot be empty".to_string()));
        }
        // append /* suffix for prefix matching (server requirement)
        let suffix = if prefix.ends_with('/') || prefix.ends_with("/*") {
            ""
        } else {
            "/*"
        };
        let url = format!("{}/kv/subscribe/{}{}", self.base_url, prefix, suffix);
        self.create_sse_stream(&url).await
    }

    /// Subscribe to changes for all keys
    pub async fn subscribe_all(
        &self,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>, Error> {
        let url = format!("{}/kv/subscribe/*", self.base_url);
        self.create_sse_stream(&url).await
    }

    // create an SSE stream with auto-reconnection and exponential backoff
    async fn create_sse_stream(
        &self,
        url: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>, Error> {
        let url = url.to_string();
        let client = self.http_client.clone();

        let stream = async_stream::stream! {
            let mut delay = Duration::from_secs(1); // 1s initial
            let max_delay = Duration::from_secs(30); // 30s max

            loop {
                match Self::connect_sse(&client, &url).await {
                    Ok(mut event_stream) => {
                        // reset delay on successful connection
                        delay = Duration::from_secs(1);

                        // yield events from the stream
                        while let Some(result) = event_stream.next().await {
                            match result {
                                Ok(event) => yield Ok(event),
                                Err(e) => {
                                    // connection error, will reconnect
                                    yield Err(e);
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        // connection failed, yield error and retry after delay
                        yield Err(e);
                    }
                }

                // wait before reconnecting with exponential backoff
                sleep(delay).await;
                delay = std::cmp::min(delay * 2, max_delay);
            }
        };

        Ok(Box::pin(stream))
    }

    // connect to SSE endpoint and return a stream of events
    async fn connect_sse(
        client: &reqwest::Client,
        url: &str,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Event, Error>> + Send>>, Error> {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Connection(format!("failed to connect: {}", e)))?;

        if !response.status().is_success() {
            return Err(Error::from(response.error_for_status().unwrap_err()));
        }

        let stream = response.bytes_stream().map(|result| {
            result.map_err(|e| Error::Connection(format!("stream read error: {}", e)))
        });

        let event_stream = Self::parse_sse_stream(Box::pin(stream));
        Ok(Box::pin(event_stream))
    }

    // parse SSE stream into Event objects
    fn parse_sse_stream(
        stream: Pin<Box<dyn Stream<Item = Result<bytes::Bytes, Error>> + Send>>,
    ) -> impl Stream<Item = Result<Event, Error>> + Send {
        async_stream::stream! {
            let mut buffer = String::new();
            let mut event_data = String::new();

            futures::pin_mut!(stream);

            while let Some(result) = stream.next().await {
                match result {
                    Ok(chunk) => {
                        let chunk_str = String::from_utf8_lossy(&chunk);
                        buffer.push_str(&chunk_str);

                        // process complete lines
                        while let Some(pos) = buffer.find('\n') {
                            let line = buffer[..pos].trim_end_matches('\r').to_string();
                            buffer.drain(..=pos);

                            if let Some(data) = line.strip_prefix("data:") {
                                event_data.push_str(data.trim());
                            } else if line.is_empty() && !event_data.is_empty() {
                                // end of event, parse JSON
                                match serde_json::from_str::<Event>(&event_data) {
                                    Ok(event) => yield Ok(event),
                                    Err(e) => {
                                        yield Err(Error::Connection(format!(
                                            "failed to parse event: {}",
                                            e
                                        )));
                                    }
                                }
                                event_data.clear();
                            }
                        }
                    }
                    Err(e) => {
                        yield Err(e);
                        break;
                    }
                }
            }
        }
    }
}
