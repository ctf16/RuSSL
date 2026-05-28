use crate::scanner::Target;
use anyhow::{anyhow, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use serde::Serialize;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

#[derive(Serialize, Debug, Default)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub is_expired: bool,
    pub key_algorithm: String,
    pub signature_algorithm: String,
    pub chain_depth: usize,
}

/// Custom verifier that captures raw DER certs without verifying them.
#[derive(Debug)]
struct CertCapture {
    certs: Mutex<Vec<Vec<u8>>>,
}

impl CertCapture {
    fn new() -> Arc<Self> {
        Arc::new(Self { certs: Mutex::new(vec![]) })
    }
}

impl ServerCertVerifier for CertCapture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut certs = self.certs.lock().unwrap();
        certs.push(end_entity.to_vec());
        for i in intermediates {
            certs.push(i.to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

pub async fn inspect(target: &Target) -> Result<CertInfo> {
    let capture = CertCapture::new();

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(target.addr()).await?;
    let server_name = ServerName::try_from(target.host.as_str())
        .map_err(|e| anyhow!("Invalid server name: {e}"))?
        .to_owned();

    connector.connect(server_name, stream).await?;

    let certs = capture.certs.lock().unwrap().clone();
    let leaf = certs.first().ok_or_else(|| anyhow!("No certificate received"))?;

    let (_, cert) = parse_x509_certificate(leaf)
        .map_err(|e| anyhow!("Parse error: {e}"))?;

    let now = chrono::Utc::now();
    let not_after = cert.validity().not_after.to_datetime();
    let not_before = cert.validity().not_before.to_datetime();
    let days_remaining = (not_after.unix_timestamp() - now.timestamp()) / 86400;

    let sans = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| {
            ext.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    GeneralName::DNSName(s) => Some(s.to_string()),
                    GeneralName::IPAddress(ip) => Some(format!("{ip:?}")),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(CertInfo {
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        sans,
        not_before: not_before.to_string(),
        not_after: not_after.to_string(),
        days_remaining,
        is_expired: days_remaining < 0,
        key_algorithm: oid_name(&cert.public_key().algorithm.algorithm.to_string()).to_string(),
        signature_algorithm: oid_name(&cert.signature_algorithm.algorithm.to_string()).to_string(),
        chain_depth: certs.len(),
    })
}

/// Map well-known OID dotted strings to human-readable algorithm names.
/// Unknown OIDs fall through as-is so nothing is silently lost.
fn oid_name(oid: &str) -> &str {
    match oid {
        // Public key algorithms
        "1.2.840.10045.2.1"      => "EC",
        "1.2.840.113549.1.1.1"   => "RSA",
        "1.3.101.112"            => "Ed25519",
        "1.3.101.110"            => "X25519",
        // Signature algorithms
        "1.2.840.10045.4.3.2"    => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3"    => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4"    => "ecdsa-with-SHA512",
        "1.2.840.113549.1.1.5"   => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11"  => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12"  => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13"  => "sha512WithRSAEncryption",
        other                    => other,
    }
}
