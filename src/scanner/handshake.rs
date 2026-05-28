use crate::error::ScanError;
use crate::scanner::{with_timeout, Target};
use rustls::ClientConfig;
use serde::Serialize;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Serialize, Debug)]
pub struct ProtocolResult {
    pub version: String,
    pub supported: bool,
    pub negotiated_cipher: Option<String>,
    pub negotiated_group: Option<String>,
}

/// Returned by [`attempt_handshake`] on success.
pub struct HandshakeInfo {
    pub cipher: Option<String>,
    pub group: Option<String>,
}

pub async fn probe_protocols(
    target: &Target,
    timeout_secs: u64,
) -> Result<Vec<ProtocolResult>, ScanError> {
    // rustls 0.23: builder_with_protocol_versions goes straight to WantsVerifier state.
    let versions: &[(&rustls::SupportedProtocolVersion, &str)] = &[
        (&rustls::version::TLS12, "TLS 1.2"),
        (&rustls::version::TLS13, "TLS 1.3"),
    ];

    let mut results = vec![];

    for (version, label) in versions {
        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
            let _ = root_store.add(cert);
        }

        let config = ClientConfig::builder_with_protocol_versions(&[version])
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let (supported, negotiated_cipher, negotiated_group) =
            match attempt_handshake(target, Arc::new(config), timeout_secs).await {
                Ok(info) => (true, info.cipher, info.group),
                Err(_) => (false, None, None),
            };

        results.push(ProtocolResult {
            version: label.to_string(),
            supported,
            negotiated_cipher,
            negotiated_group,
        });
    }

    Ok(results)
}

pub async fn attempt_handshake(
    target: &Target,
    config: Arc<ClientConfig>,
    timeout_secs: u64,
) -> Result<HandshakeInfo, ScanError> {
    with_timeout(timeout_secs, async move {
        let connector = TlsConnector::from(config);
        let stream = TcpStream::connect(target.addr()).await?;
        let server_name = rustls::pki_types::ServerName::try_from(target.host.as_str())
            .map_err(|e| ScanError::InvalidName(e.to_string()))?
            .to_owned();
        let tls_stream = connector.connect(server_name, stream).await?;
        let conn = tls_stream.get_ref().1;
        let cipher = conn
            .negotiated_cipher_suite()
            .map(|s| format!("{:?}", s.suite()));
        let group = conn
            .negotiated_key_exchange_group()
            .map(|g| format!("{:?}", g.name()));
        Ok(HandshakeInfo { cipher, group })
    })
    .await
}
