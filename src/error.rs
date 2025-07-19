use thiserror::Error;

/// Error types for the 2captcha library
#[derive(Error, Debug)]
pub enum TwoCaptchaError {
    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("API error: {0}")]
    Api(String),

    #[error("Timeout error: {0}")]
    Timeout(String),

    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),

    #[error("JSON parsing error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
}

/// Alias for Result with TwoCaptchaError
pub type Result<T> = std::result::Result<T, TwoCaptchaError>;

/// Base exception type for solver exceptions
pub trait SolverExceptions: std::error::Error + Send + Sync {}

impl SolverExceptions for TwoCaptchaError {}
