use thiserror::Error;

#[allow(dead_code)] // Phase 2+: used when typed errors replace anyhow at call sites
#[derive(Error, Debug)]
pub enum ScanError {
    #[error("Connection failed: {0}")]
    Connection(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("Certificate parse error: {0}")]
    CertParse(String),
    #[error("Timeout")]
    Timeout,
}
