/// Error types for the Stash client
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Key was not found
    #[error("key not found")]
    NotFound,

    /// Authentication failed
    #[error("unauthorized")]
    Unauthorized,

    /// Access forbidden (permission denied)
    #[error("forbidden")]
    Forbidden,

    /// Decryption failed
    #[error("decryption failed: {0}")]
    Decryption(String),

    /// Connection or network error
    #[error("connection failed: {0}")]
    Connection(String),

    /// HTTP error response
    #[error("HTTP {status}: {message}")]
    Response { status: u16, message: String },
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            Error::Connection("request timeout".to_string())
        } else if err.is_connect() {
            Error::Connection(format!("connection failed: {}", err))
        } else if let Some(status) = err.status() {
            match status.as_u16() {
                401 => Error::Unauthorized,
                403 => Error::Forbidden,
                404 => Error::NotFound,
                code => Error::Response {
                    status: code,
                    message: err.to_string(),
                },
            }
        } else {
            Error::Connection(err.to_string())
        }
    }
}
