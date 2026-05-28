use crate::error::ScanError;
use crate::scanner::{with_timeout, ScanOpts, Target};
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
    /// Public key size in bits, when it can be determined from the SPKI.
    pub key_bits: Option<usize>,
    /// True when the key is below modern minimums (RSA < 2048, EC < 256).
    pub weak_key: bool,
    pub signature_algorithm: String,
    /// Validation level derived from CA/Browser Forum policy OIDs, or inferred
    /// from the presence of an organization in the subject.
    pub validation_level: String,
    /// OCSP revocation status when `--ocsp` is set: `Good` / `Revoked` /
    /// `Unknown`, or a descriptive message. `None` when the check was not run.
    pub ocsp_status: Option<String>,
    /// Number of Certificate Transparency log entries crt.sh reports when
    /// `--ct` is set. `None` when the check was not run or failed.
    pub ct_log_entries: Option<usize>,
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

pub async fn inspect(target: &Target, opts: &ScanOpts) -> Result<CertInfo, ScanError> {
    let capture = CertCapture::new();

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();

    let certs: Vec<Vec<u8>> = with_timeout(opts.timeout_secs, async move {
        let connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(target.addr()).await?;
        let server_name = ServerName::try_from(target.host.as_str())
            .map_err(|e| ScanError::InvalidName(e.to_string()))?
            .to_owned();
        connector.connect(server_name, stream).await?;
        Ok(capture.certs.lock().unwrap().clone())
    })
    .await?;

    // Parse the leaf into owned `CertInfo` fields inside this block so the
    // borrow of `certs` ends before the optional network checks await below.
    let mut info = {
        let leaf = certs.first().ok_or(ScanError::NoCertificate)?;
        let (_, cert) =
            parse_x509_certificate(leaf).map_err(|e| ScanError::CertParse(e.to_string()))?;

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

        let key_algorithm =
            oid_name(&cert.public_key().algorithm.algorithm.to_string()).to_string();
        let key_bits = cert.public_key().parsed().ok().map(|k| k.key_size());
        let weak_key = is_weak_key(&key_algorithm, key_bits);

        let policy_oids: Vec<String> = cert
            .extensions()
            .iter()
            .filter_map(|ext| match ext.parsed_extension() {
                ParsedExtension::CertificatePolicies(policies) => Some(policies),
                _ => None,
            })
            .flatten()
            .map(|info| info.policy_id.to_string())
            .collect();
        let has_org = cert.subject().iter_organization().next().is_some();
        let validation_level = classify_validation(&policy_oids, has_org).to_string();

        CertInfo {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            sans,
            not_before: not_before.to_string(),
            not_after: not_after.to_string(),
            days_remaining,
            is_expired: days_remaining < 0,
            key_algorithm,
            key_bits,
            weak_key,
            signature_algorithm: oid_name(&cert.signature_algorithm.algorithm.to_string())
                .to_string(),
            validation_level,
            ocsp_status: None,
            ct_log_entries: None,
            chain_depth: certs.len(),
        }
    };

    if opts.check_ocsp {
        info.ocsp_status = Some(crate::scanner::ocsp::check(&certs, opts.timeout_secs).await);
    }

    if opts.check_ct {
        match crate::scanner::ct::entry_count(&target.host, opts.timeout_secs).await {
            Ok(count) => info.ct_log_entries = Some(count),
            Err(e) => eprintln!("CT lookup failed for {}: {e}", target.host),
        }
    }

    Ok(info)
}

/// Flag keys below current minimums: RSA/DSA < 2048 bits, EC < 256 bits.
/// `bits == None` means the size could not be parsed, which is treated as
/// not-weak to avoid false alarms on exotic key types.
fn is_weak_key(algorithm: &str, bits: Option<usize>) -> bool {
    match bits {
        Some(b) => match algorithm {
            "RSA" | "DSA" => b < 2048,
            "EC" => b < 256,
            // Modern EdDSA/X25519 keys are ~128-bit security at 256-bit size.
            _ => false,
        },
        None => false,
    }
}

/// Classify the certificate validation level using the CA/Browser Forum
/// reserved certificate-policy identifiers (RFC-registered under 2.23.140.1).
/// When no standardized policy OID is present, fall back to a subject-based
/// heuristic: presence of an organization implies OV, otherwise DV.
fn classify_validation(policy_oids: &[String], has_org: bool) -> &'static str {
    for oid in policy_oids {
        match oid.as_str() {
            "2.23.140.1.1" => return "EV",
            "2.23.140.1.2.2" => return "OV",
            "2.23.140.1.2.3" => return "IV",
            "2.23.140.1.2.1" => return "DV",
            _ => {}
        }
    }
    if has_org {
        "OV (inferred)"
    } else {
        "DV (inferred)"
    }
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

#[cfg(test)]
mod tests {
    use super::{classify_validation, is_weak_key};

    #[test]
    fn rsa_below_2048_is_weak() {
        assert!(is_weak_key("RSA", Some(1024)));
        assert!(is_weak_key("RSA", Some(2047)));
        assert!(!is_weak_key("RSA", Some(2048)));
        assert!(!is_weak_key("RSA", Some(4096)));
    }

    #[test]
    fn ec_below_256_is_weak() {
        assert!(is_weak_key("EC", Some(192)));
        assert!(!is_weak_key("EC", Some(256)));
        assert!(!is_weak_key("EC", Some(384)));
    }

    #[test]
    fn unknown_size_is_not_flagged() {
        assert!(!is_weak_key("RSA", None));
        assert!(!is_weak_key("EC", None));
    }

    #[test]
    fn modern_eddsa_is_not_weak() {
        assert!(!is_weak_key("Ed25519", Some(256)));
    }

    #[test]
    fn cab_policy_oids_classify_directly() {
        assert_eq!(classify_validation(&["2.23.140.1.1".into()], false), "EV");
        assert_eq!(classify_validation(&["2.23.140.1.2.2".into()], false), "OV");
        assert_eq!(classify_validation(&["2.23.140.1.2.1".into()], true), "DV");
    }

    #[test]
    fn cab_oid_wins_over_unrelated_policy() {
        assert_eq!(
            classify_validation(&["1.3.6.1.4.1.99".into(), "2.23.140.1.1".into()], false),
            "EV"
        );
    }

    #[test]
    fn falls_back_to_subject_heuristic() {
        assert_eq!(classify_validation(&[], true), "OV (inferred)");
        assert_eq!(classify_validation(&[], false), "DV (inferred)");
        assert_eq!(
            classify_validation(&["1.3.6.1.4.1.99".into()], true),
            "OV (inferred)"
        );
    }
}