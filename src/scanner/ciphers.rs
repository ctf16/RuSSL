use crate::scanner::Target;
use anyhow::Result;
use rustls::{ClientConfig, SupportedCipherSuite};
use rustls::crypto::{ring as crypto_ring, CryptoProvider};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::Semaphore;

#[derive(Serialize, Debug)]
pub struct CipherResult {
    pub suite: String,
    pub accepted: bool,
    pub strength: String,
}

/// All ring-backed suites we probe. TLS 1.3 suites will fail on a TLS-1.2-only
/// endpoint (and vice-versa); that's expected — we just record accepted/rejected.
const PROBE_SUITES: &[SupportedCipherSuite] = &[
    rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
    rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
];

pub async fn enumerate(target: &Target) -> Result<Vec<CipherResult>> {
    let semaphore = Arc::new(Semaphore::new(5));
    let mut handles = vec![];

    for suite in PROBE_SUITES {
        let sem = semaphore.clone();
        let target = target.clone();
        let suite = *suite;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            let mut root_store = rustls::RootCertStore::empty();
            for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
                let _ = root_store.add(cert);
            }

            // rustls 0.23: restrict cipher suites via a custom CryptoProvider.
            let provider = CryptoProvider {
                cipher_suites: vec![suite],
                ..crypto_ring::default_provider()
            };

            let config = ClientConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(root_store)
                .with_no_client_auth();

            let accepted = crate::scanner::handshake::attempt_handshake(
                &target,
                Arc::new(config),
            )
            .await
            .is_ok();

            CipherResult {
                suite: format!("{:?}", suite.suite()),
                accepted,
                strength: classify(suite),
            }
        }));
    }

    let mut results = vec![];
    for h in handles {
        if let Ok(r) = h.await {
            results.push(r);
        }
    }
    Ok(results)
}

fn classify(suite: SupportedCipherSuite) -> String {
    let name = format!("{:?}", suite.suite());
    if name.contains("CHACHA20") || name.contains("AES_256") {
        "Strong".into()
    } else if name.contains("AES_128") {
        "Adequate".into()
    } else {
        "Weak".into()
    }
}
