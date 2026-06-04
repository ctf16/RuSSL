pub mod cert;
pub mod ciphers;
pub mod connection;
pub mod ct;
pub(crate) mod der;
pub mod handshake;
pub(crate) mod http;
pub mod ocsp;
pub mod vulns;

use crate::error::ScanError;
use serde::Serialize;
use std::future::Future;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

impl Target {
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

pub struct ScanOpts {
    pub enumerate_ciphers: bool,
    pub check_vulns: bool,
    pub check_ocsp: bool,
    pub check_ct: bool,
    pub check_connection: bool,
    pub timeout_secs: u64,
}

/// Run `fut` under the configured timeout. A `timeout_secs` of 0 disables the
/// limit. On expiry the in-flight future is dropped and [`ScanError::Timeout`]
/// is returned.
pub(crate) async fn with_timeout<F, T>(timeout_secs: u64, fut: F) -> Result<T, ScanError>
where
    F: Future<Output = Result<T, ScanError>>,
{
    if timeout_secs == 0 {
        return fut.await;
    }
    match tokio::time::timeout(Duration::from_secs(timeout_secs), fut).await {
        Ok(res) => res,
        Err(_) => Err(ScanError::Timeout),
    }
}

#[derive(Serialize, Debug)]
pub struct ScanResult {
    pub host: String,
    pub port: u16,
    pub certificate: cert::CertInfo,
    pub protocols: Vec<handshake::ProtocolResult>,
    pub cipher_suites: Vec<ciphers::CipherResult>,
    pub vulnerabilities: Vec<vulns::VulnResult>,
    pub connection: Option<connection::ConnectionProperties>,
}

pub async fn run_scan(target: &Target, opts: &ScanOpts) -> Result<ScanResult, ScanError> {
    eprintln!("Scanning {}:{}...\n", target.host, target.port);

    let certificate = cert::inspect(target, opts).await?;
    let protocols = handshake::probe_protocols(target, opts.timeout_secs).await?;

    let cipher_suites = if opts.enumerate_ciphers {
        ciphers::enumerate(target, opts.timeout_secs).await?
    } else {
        vec![]
    };

    let vulnerabilities = if opts.check_vulns {
        vulns::check_all(target, &protocols).await?
    } else {
        vec![]
    };

    let connection = if opts.check_connection {
        match connection::inspect(target, opts, &protocols).await {
            Ok(props) => Some(props),
            Err(e) => {
                eprintln!("Connection property checks failed: {e}");
                None
            }
        }
    } else {
        None
    };

    Ok(ScanResult {
        host: target.host.clone(),
        port: target.port,
        certificate,
        protocols,
        cipher_suites,
        vulnerabilities,
        connection,
    })
}

#[cfg(test)]
mod tests {
    use super::{with_timeout, ScanError};
    use std::time::Duration;

    #[tokio::test(start_paused = true)]
    async fn elapsed_future_yields_timeout() {
        let result: Result<(), ScanError> = with_timeout(1, async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok(())
        })
        .await;
        assert!(matches!(result, Err(ScanError::Timeout)));
    }

    #[tokio::test(start_paused = true)]
    async fn fast_future_completes() {
        let result = with_timeout(5, async { Ok::<_, ScanError>(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn zero_disables_timeout() {
        let result = with_timeout(0, async { Ok::<_, ScanError>(7) }).await;
        assert_eq!(result.unwrap(), 7);
    }
}