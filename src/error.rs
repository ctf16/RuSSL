use thiserror::Error;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Connection failed: {0}")]
    Connection(#[from] std::io::Error),
    #[error("Invalid server name: {0}")]
    InvalidName(String),
    #[error("No certificate received from server")]
    NoCertificate,
    #[error("Certificate parse error: {0}")]
    CertParse(String),
    #[error("Operation timed out")]
    Timeout,
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),
}
