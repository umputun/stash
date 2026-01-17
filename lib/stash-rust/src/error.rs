/// error types for stash client operations
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// key not found in stash
    #[error("key not found")]
    NotFound,

    /// authentication token is invalid or missing
    #[error("unauthorized")]
    Unauthorized,

    /// authenticated but lacks permission for the operation
    #[error("forbidden")]
    Forbidden,

    /// decryption failed (zk encryption)
    #[error("decryption failed: {0}")]
    Decryption(String),

    /// connection or network error
    #[error("connection failed: {0}")]
    Connection(String),

    /// http error response
    #[error("HTTP {status}: {message}")]
    Response { status: u16, message: String },

    /// invalid configuration or parameters
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            Error::Connection("timeout".to_string())
        } else if err.is_connect() {
            Error::Connection(err.to_string())
        } else if let Some(status) = err.status() {
            match status.as_u16() {
                404 => Error::NotFound,
                401 => Error::Unauthorized,
                403 => Error::Forbidden,
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

impl From<reqwest_middleware::Error> for Error {
    fn from(err: reqwest_middleware::Error) -> Self {
        // try to extract the underlying reqwest error for better error handling
        match err {
            reqwest_middleware::Error::Middleware(e) => Error::Connection(e.to_string()),
            reqwest_middleware::Error::Reqwest(e) => Error::from(e),
        }
    }
}
