use crate::error::Error;
use crate::types::{Event, Format, KeyInfo};
use futures::stream::{Stream, StreamExt};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use std::pin::Pin;
use std::time::Duration;
use tokio::time::sleep;

#[cfg(feature = "zk")]
use crate::zk::{is_zk_encrypted, ZKCrypto};

/// Configuration options for the Stash client.
///
/// # Examples
///
/// ```
/// use stash::ClientOptions;
/// use std::time::Duration;
///
/// let options = ClientOptions {
///     token: Some("my-api-token".to_string()),
///     timeout: Some(Duration::from_secs(10)),
///     zk_key: Some("my-passphrase-min-16".to_string()),
/// };
/// ```
#[derive(Default, Clone)]
pub struct ClientOptions {
    /// API token for authentication.
    ///
    /// When set, the token is sent as a Bearer token in the Authorization header.
    pub token: Option<String>,

    /// Request timeout duration.
    ///
    /// Default is 30 seconds if not specified.
    pub timeout: Option<Duration>,

    /// Zero-knowledge encryption passphrase.
    ///
    /// When set, all values are automatically encrypted client-side before sending to the server
    /// and decrypted when retrieved. The passphrase must be at least 16 characters.
    ///
    /// Requires the `zk` feature to be enabled.
    pub zk_key: Option<String>,
}

/// Client for interacting with the Stash key-value service.
///
/// The client is `Clone + Send + Sync` and can be safely shared across threads.
/// All methods are async and return `Result<T, Error>`.
///
/// # Examples
///
/// ```no_run
/// use stash::Client;
///
/// #[tokio::main]
/// async fn main() -> Result<(), stash::Error> {
///     let client = Client::new("http://localhost:8080")?;
///
///     client.set("app/config", "value", None).await?;
///     let value = client.get("app/config").await?;
///
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct Client {
    http_client: reqwest::Client,
    base_url: String,
    #[allow(dead_code)] // used for zk_key access (feature-gated)
    options: ClientOptions,
}

impl Client {
    /// Creates a new client with default options.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Stash server (e.g., "http://localhost:8080")
    ///
    /// # Errors
    ///
    /// Returns an error if the base URL is empty or the HTTP client cannot be created.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stash::Client;
    ///
    /// let client = Client::new("http://localhost:8080")?;
    /// # Ok::<(), stash::Error>(())
    /// ```
    pub fn new(base_url: &str) -> Result<Self, Error> {
        Self::with_options(base_url, ClientOptions::default())
    }

    /// Creates a new client with custom options.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Stash server
    /// * `options` - Configuration options for the client
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The base URL is empty
    /// - The zk_key is provided but is less than 16 characters
    /// - The HTTP client cannot be created
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use stash::{Client, ClientOptions};
    /// use std::time::Duration;
    ///
    /// let client = Client::with_options("http://localhost:8080", ClientOptions {
    ///     token: Some("my-token".to_string()),
    ///     timeout: Some(Duration::from_secs(10)),
    ///     ..Default::default()
    /// })?;
    /// # Ok::<(), stash::Error>(())
    /// ```
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

    /// Checks server connectivity by sending a ping request.
    ///
    /// # Errors
    ///
    /// Returns an error if the server is unreachable or returns an error response.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// client.ping().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn ping(&self) -> Result<(), Error> {
        let url = format!("{}/ping", self.base_url);
        let response = self.http_client.get(&url).send().await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(Error::from(response.error_for_status().unwrap_err()))
        }
    }

    /// Gets a value as a UTF-8 string.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is empty
    /// - The key is not found (404)
    /// - The value is not valid UTF-8
    /// - A network or server error occurs
    /// - ZK decryption fails (if applicable)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// let value = client.get("app/config").await?;
    /// println!("Value: {}", value);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get(&self, key: &str) -> Result<String, Error> {
        let bytes = self.get_bytes(key).await?;
        String::from_utf8(bytes)
            .map_err(|e| Error::Connection(format!("invalid UTF-8 in response: {}", e)))
    }

    /// Gets a value as raw bytes.
    ///
    /// If the client has a ZK key configured and the value is ZK-encrypted,
    /// it will be automatically decrypted.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is empty
    /// - The key is not found (404)
    /// - A network or server error occurs
    /// - ZK decryption fails (if applicable)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// let bytes = client.get_bytes("app/binary").await?;
    /// println!("Size: {} bytes", bytes.len());
    /// # Ok(())
    /// # }
    /// ```
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

    /// Gets a value or returns a default if the key doesn't exist.
    ///
    /// This method never returns an error - it returns the default value
    /// for any error (not found, network error, etc.).
    ///
    /// # Arguments
    ///
    /// * `key` - The key to retrieve
    /// * `default` - The default value to return if the key doesn't exist or an error occurs
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// let value = client.get_or_default("app/config", "default-value").await;
    /// println!("Value: {}", value);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_or_default(&self, key: &str, default: &str) -> String {
        match self.get(key).await {
            Ok(value) => value,
            Err(_) => default.to_string(),
        }
    }

    /// Gets metadata about a key without retrieving its value.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to get info for
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is empty
    /// - The key is not found (404)
    /// - A network or server error occurs
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// let info = client.info("app/config").await?;
    /// println!("Created: {}, Size: {} bytes", info.created, info.size);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn info(&self, key: &str) -> Result<KeyInfo, Error> {
        if key.is_empty() {
            return Err(Error::Connection("key cannot be empty".to_string()));
        }
        let keys = self.list(Some(key)).await?;
        keys.into_iter()
            .find(|k| k.key == key)
            .ok_or(Error::NotFound)
    }

    /// Sets a string value for a key.
    ///
    /// If the client has a ZK key configured, the value will be automatically
    /// encrypted before sending to the server.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to set
    /// * `value` - The string value to store
    /// * `format` - Optional format hint for syntax highlighting
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is empty
    /// - A network or server error occurs
    /// - ZK encryption fails (if applicable)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::{Client, Format};
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// client.set("app/config", "value", Some(Format::Json)).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn set(&self, key: &str, value: &str, format: Option<Format>) -> Result<(), Error> {
        self.set_bytes(key, value.as_bytes(), format).await
    }

    /// Sets a binary value for a key.
    ///
    /// If the client has a ZK key configured, the value will be automatically
    /// encrypted before sending to the server.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to set
    /// * `value` - The binary value to store
    /// * `format` - Optional format hint for syntax highlighting
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is empty
    /// - A network or server error occurs
    /// - ZK encryption fails (if applicable)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// client.set_bytes("app/binary", &[1, 2, 3], None).await?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Deletes a key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to delete
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key is empty
    /// - The key is not found (404)
    /// - A network or server error occurs
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// client.delete("app/config").await?;
    /// # Ok(())
    /// # }
    /// ```
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

    /// Lists all keys, optionally filtered by prefix.
    ///
    /// When auth is enabled, only keys the caller has read permission for are returned.
    ///
    /// # Arguments
    ///
    /// * `prefix` - Optional prefix to filter keys (e.g., "app/" returns all keys starting with "app/")
    ///
    /// # Errors
    ///
    /// Returns an error if a network or server error occurs.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::Client;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// // list all keys
    /// let all_keys = client.list(None).await?;
    ///
    /// // list keys with prefix
    /// let app_keys = client.list(Some("app/")).await?;
    /// for key in app_keys {
    ///     println!("{}: {} bytes", key.key, key.size);
    /// }
    /// # Ok(())
    /// # }
    /// ```
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

    /// Subscribes to real-time change events for a specific key.
    ///
    /// Returns a stream that yields events whenever the key is created, updated, or deleted.
    /// The stream automatically reconnects with exponential backoff (1s initial, 30s max)
    /// if the connection is lost.
    ///
    /// # Arguments
    ///
    /// * `key` - The exact key to subscribe to
    ///
    /// # Errors
    ///
    /// Returns an error if the key is empty.
    /// Connection errors are yielded as stream items, not as immediate errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::Client;
    /// # use futures::StreamExt;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// let mut stream = client.subscribe("app/config").await?;
    /// while let Some(event) = stream.next().await {
    ///     let event = event?;
    ///     println!("{}: {} at {}", event.action, event.key, event.timestamp);
    /// }
    /// # Ok(())
    /// # }
    /// ```
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

    /// Subscribes to real-time change events for all keys with a given prefix.
    ///
    /// Returns a stream that yields events whenever any key with the specified prefix
    /// is created, updated, or deleted. The stream automatically reconnects with
    /// exponential backoff (1s initial, 30s max) if the connection is lost.
    ///
    /// # Arguments
    ///
    /// * `prefix` - The prefix to subscribe to (e.g., "app/" for all keys starting with "app/")
    ///
    /// # Errors
    ///
    /// Returns an error if the prefix is empty.
    /// Connection errors are yielded as stream items, not as immediate errors.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::Client;
    /// # use futures::StreamExt;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// let mut stream = client.subscribe_prefix("app/").await?;
    /// while let Some(event) = stream.next().await {
    ///     let event = event?;
    ///     println!("{}: {}", event.action, event.key);
    /// }
    /// # Ok(())
    /// # }
    /// ```
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

    /// Subscribes to real-time change events for all keys.
    ///
    /// Returns a stream that yields events whenever any key is created, updated,
    /// or deleted. The stream automatically reconnects with exponential backoff
    /// (1s initial, 30s max) if the connection is lost.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use stash::Client;
    /// # use futures::StreamExt;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), stash::Error> {
    /// # let client = Client::new("http://localhost:8080")?;
    /// let mut stream = client.subscribe_all().await?;
    /// while let Some(event) = stream.next().await {
    ///     let event = event?;
    ///     println!("{}: {}", event.action, event.key);
    /// }
    /// # Ok(())
    /// # }
    /// ```
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
