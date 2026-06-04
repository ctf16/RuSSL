//! Connection-property checks (roadmap Phase 2).
//!
//! These describe how the TLS connection itself is configured, beyond the raw
//! protocol versions probed in [`crate::scanner::handshake`]:
//!
//! * **Forward secrecy** — whether the negotiated suites use ephemeral key
//!   exchange. Derived from the already-collected protocol results; no extra
//!   network traffic.
//! * **OCSP stapling** — whether the server stapled an OCSP response into the
//!   handshake. rustls always offers the `status_request` extension, so a
//!   stapled response reaches our certificate verifier; we observe its length.
//! * **Session resumption** — whether the server issues TLS 1.3 tickets or a
//!   resumable TLS 1.2 session. Detected with a recording
//!   [`ClientSessionStore`] that flags `insert_tls13_ticket` /
//!   `set_tls12_session` calls.
//! * **SNI behaviour** — compares the certificate served with SNI against the
//!   one served without it (achieved by presenting an IP `ServerName`, for
//!   which rustls omits the SNI extension).
//! * **HSTS** — an HTTPS GET on the target port, inspecting the
//!   `Strict-Transport-Security` response header. (The header is only
//!   meaningful over TLS, so it is read over HTTPS rather than cleartext.)
//!
//! Every probe degrades gracefully: a failed sub-check yields a descriptive
//! "unknown"/`None` rather than aborting the scan.

use crate::error::ScanError;
use crate::scanner::cert::CertCapture;
use crate::scanner::handshake::ProtocolResult;
use crate::scanner::http::{self, Scheme};
use crate::scanner::{with_timeout, ScanOpts, Target};
use rustls::client::{
    ClientSessionMemoryCache, ClientSessionStore, Resumption, Tls12ClientSessionValue,
    Tls13ClientSessionValue,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, NamedGroup};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

/// How long the best-effort post-handshake read may take when pumping the
/// connection for TLS 1.3 `NewSessionTicket` messages.
const TICKET_PUMP_SECS: u64 = 3;

#[derive(Serialize, Debug)]
pub struct ConnectionProperties {
    pub forward_secrecy: ForwardSecrecy,
    pub ocsp_stapling: OcspStapling,
    pub session_resumption: SessionResumption,
    pub sni: SniBehavior,
    /// `None` when the HSTS probe could not complete (e.g. the target does not
    /// speak HTTPS on this port, or its certificate is untrusted).
    pub hsts: Option<Hsts>,
}

#[derive(Serialize, Debug)]
pub struct ForwardSecrecy {
    /// True when every supported protocol negotiated a forward-secret suite.
    pub all_forward_secret: bool,
    pub protocols: Vec<FsProtocol>,
}

#[derive(Serialize, Debug)]
pub struct FsProtocol {
    pub version: String,
    pub cipher: Option<String>,
    pub forward_secret: bool,
}

#[derive(Serialize, Debug)]
pub struct OcspStapling {
    pub stapled: bool,
    pub response_len: usize,
}

#[derive(Serialize, Debug)]
pub struct SessionResumption {
    /// Server issued a TLS 1.3 `NewSessionTicket`.
    pub tls13_ticket: bool,
    /// Server issued a resumable TLS 1.2 session (session id or RFC 5077 ticket).
    pub tls12_session: bool,
    /// True when either resumption mechanism is offered.
    pub supported: bool,
}

#[derive(Serialize, Debug)]
pub struct SniBehavior {
    /// One of `same-certificate`, `different-certificate`,
    /// `rejected-without-sni`, `not-applicable` (IP target), or `unknown`.
    pub outcome: &'static str,
    pub with_sni_subject: Option<String>,
    pub without_sni_subject: Option<String>,
}

#[derive(Serialize, Debug)]
pub struct Hsts {
    pub present: bool,
    pub max_age: Option<u64>,
    pub include_subdomains: bool,
    pub preload: bool,
    /// The raw header value, for transparency.
    pub header: Option<String>,
}

pub async fn inspect(
    target: &Target,
    opts: &ScanOpts,
    protocols: &[ProtocolResult],
) -> Result<ConnectionProperties, ScanError> {
    // The three probes open independent connections; run them concurrently.
    let (primary, no_sni, hsts) = tokio::join!(
        probe_primary(target, opts.timeout_secs),
        probe_no_sni(target, opts.timeout_secs),
        probe_hsts(target, opts.timeout_secs),
    );
    let primary = primary?;

    Ok(ConnectionProperties {
        forward_secrecy: forward_secrecy(protocols),
        ocsp_stapling: primary.ocsp,
        session_resumption: primary.session,
        sni: classify_sni(&target.host, primary.leaf.as_deref(), &no_sni),
        hsts,
    })
}

/// Results gathered from a single capturing handshake performed *with* SNI.
struct Primary {
    /// Leaf certificate DER, used as the SNI baseline.
    leaf: Option<Vec<u8>>,
    ocsp: OcspStapling,
    session: SessionResumption,
}

/// A `ClientSessionStore` that delegates to an in-memory cache while recording
/// whether the server ever offered resumable session material.
#[derive(Debug)]
struct RecordingStore {
    inner: ClientSessionMemoryCache,
    tls12: AtomicBool,
    tls13: AtomicBool,
}

impl RecordingStore {
    fn new() -> Self {
        Self {
            inner: ClientSessionMemoryCache::new(8),
            tls12: AtomicBool::new(false),
            tls13: AtomicBool::new(false),
        }
    }
}

impl ClientSessionStore for RecordingStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.inner.set_kx_hint(server_name, group);
    }

    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.inner.kx_hint(server_name)
    }

    fn set_tls12_session(&self, server_name: ServerName<'static>, value: Tls12ClientSessionValue) {
        self.tls12.store(true, Ordering::Relaxed);
        self.inner.set_tls12_session(server_name, value);
    }

    fn tls12_session(&self, server_name: &ServerName<'_>) -> Option<Tls12ClientSessionValue> {
        self.inner.tls12_session(server_name)
    }

    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.inner.remove_tls12_session(server_name);
    }

    fn insert_tls13_ticket(&self, server_name: ServerName<'static>, value: Tls13ClientSessionValue) {
        self.tls13.store(true, Ordering::Relaxed);
        self.inner.insert_tls13_ticket(server_name, value);
    }

    fn take_tls13_ticket(&self, server_name: &ServerName<'static>) -> Option<Tls13ClientSessionValue> {
        self.inner.take_tls13_ticket(server_name)
    }
}

/// Dangerous (capture-all) verifier config, mirroring [`crate::scanner::cert`]:
/// inspection must succeed regardless of certificate validity.
fn capture_config(capture: Arc<CertCapture>) -> ClientConfig {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(capture)
        .with_no_client_auth()
}

async fn probe_primary(target: &Target, timeout_secs: u64) -> Result<Primary, ScanError> {
    let capture = CertCapture::new();
    let store = Arc::new(RecordingStore::new());

    let mut config = capture_config(capture.clone());
    config.resumption = Resumption::store(store.clone());
    let connector = TlsConnector::from(Arc::new(config));

    // The handshake itself is bounded by the configured timeout; the ticket
    // pump that follows is best-effort with its own short bound so it can never
    // discard an otherwise-successful probe.
    let mut tls = with_timeout(timeout_secs, async {
        let tcp = TcpStream::connect(target.addr()).await?;
        let name = ServerName::try_from(target.host.as_str())
            .map_err(|e| ScanError::InvalidName(e.to_string()))?
            .to_owned();
        connector.connect(name, tcp).await.map_err(ScanError::from)
    })
    .await?;

    pump_tickets(&mut tls, &target.host).await;

    let ocsp_bytes = capture.ocsp_response();
    let (tls12, tls13) = (
        store.tls12.load(Ordering::Relaxed),
        store.tls13.load(Ordering::Relaxed),
    );

    Ok(Primary {
        leaf: capture.certs().into_iter().next(),
        ocsp: OcspStapling { stapled: !ocsp_bytes.is_empty(), response_len: ocsp_bytes.len() },
        session: SessionResumption { tls13_ticket: tls13, tls12_session: tls12, supported: tls12 || tls13 },
    })
}

/// Drive one HTTP request/response round-trip so the client processes any
/// post-handshake `NewSessionTicket` records (TLS 1.3 sends them unsolicited
/// right after `Finished`). All errors are ignored — this is purely to let the
/// recording store observe a ticket; a non-HTTP service simply yields nothing.
async fn pump_tickets<S>(tls: &mut S, host: &str)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let req =
        format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: russl/0.1\r\nConnection: close\r\n\r\n");
    let _ = tokio::time::timeout(Duration::from_secs(TICKET_PUMP_SECS), async {
        tls.write_all(req.as_bytes()).await?;
        tls.flush().await?;
        let mut buf = [0u8; 2048];
        let _ = tls.read(&mut buf).await?;
        Ok::<_, std::io::Error>(())
    })
    .await;
}

/// Outcome of the no-SNI handshake.
enum NoSni {
    /// Server completed the handshake and presented this leaf certificate.
    Leaf(Vec<u8>),
    /// Server refused the connection when no SNI was sent.
    Rejected,
    /// The host could not be resolved to an address to probe.
    Unavailable,
}

async fn probe_no_sni(target: &Target, timeout_secs: u64) -> NoSni {
    // Resolve to a concrete address so we can present an IP `ServerName`;
    // rustls omits the SNI extension for IP names, giving us a no-SNI probe.
    let addr = match lookup_host(target.addr()).await {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => return NoSni::Unavailable,
        },
        Err(_) => return NoSni::Unavailable,
    };

    let capture = CertCapture::new();
    let connector = TlsConnector::from(Arc::new(capture_config(capture.clone())));
    let name = ServerName::from(addr.ip());

    let res = with_timeout(timeout_secs, async move {
        let tcp = TcpStream::connect(addr).await?;
        connector.connect(name, tcp).await.map_err(ScanError::from)?;
        Ok::<_, ScanError>(())
    })
    .await;

    match res {
        Ok(()) => match capture.certs().into_iter().next() {
            Some(leaf) => NoSni::Leaf(leaf),
            None => NoSni::Rejected,
        },
        Err(_) => NoSni::Rejected,
    }
}

async fn probe_hsts(target: &Target, timeout_secs: u64) -> Option<Hsts> {
    let resp = with_timeout(
        timeout_secs,
        http::request(Scheme::Https, &target.host, target.port, "GET", "/", &[], None),
    )
    .await;

    match resp {
        Ok(r) => Some(parse_hsts(r.header("strict-transport-security"))),
        Err(e) => {
            eprintln!("HSTS probe failed for {}: {e}", target.host);
            None
        }
    }
}

/// Parse a `Strict-Transport-Security` header value.
fn parse_hsts(header: Option<&str>) -> Hsts {
    let Some(raw) = header else {
        return Hsts {
            present: false,
            max_age: None,
            include_subdomains: false,
            preload: false,
            header: None,
        };
    };

    let mut max_age = None;
    let mut include_subdomains = false;
    let mut preload = false;
    for token in raw.split(';') {
        let token = token.trim();
        if let Some((k, v)) = token.split_once('=') {
            if k.trim().eq_ignore_ascii_case("max-age") {
                max_age = v.trim().trim_matches('"').parse::<u64>().ok();
            }
        } else if token.eq_ignore_ascii_case("includeSubDomains") {
            include_subdomains = true;
        } else if token.eq_ignore_ascii_case("preload") {
            preload = true;
        }
    }

    Hsts { present: true, max_age, include_subdomains, preload, header: Some(raw.to_string()) }
}

fn classify_sni(host: &str, with_leaf: Option<&[u8]>, no_sni: &NoSni) -> SniBehavior {
    let with_sni_subject = with_leaf.and_then(leaf_subject);

    // An IP target carries no SNI in either probe, so the comparison is moot.
    if host.parse::<std::net::IpAddr>().is_ok() {
        return SniBehavior { outcome: "not-applicable", with_sni_subject, without_sni_subject: None };
    }

    match no_sni {
        NoSni::Unavailable => {
            SniBehavior { outcome: "unknown", with_sni_subject, without_sni_subject: None }
        }
        NoSni::Rejected => SniBehavior {
            outcome: "rejected-without-sni",
            with_sni_subject,
            without_sni_subject: None,
        },
        NoSni::Leaf(no_leaf) => {
            let same = with_leaf == Some(no_leaf.as_slice());
            SniBehavior {
                outcome: if same { "same-certificate" } else { "different-certificate" },
                with_sni_subject,
                without_sni_subject: leaf_subject(no_leaf),
            }
        }
    }
}

fn leaf_subject(der: &[u8]) -> Option<String> {
    parse_x509_certificate(der).ok().map(|(_, cert)| cert.subject().to_string())
}

fn forward_secrecy(protocols: &[ProtocolResult]) -> ForwardSecrecy {
    let mut details = Vec::new();
    let mut all = true;
    for p in protocols {
        if !p.supported {
            continue;
        }
        let fs = is_forward_secret(&p.version, p.negotiated_cipher.as_deref());
        all &= fs;
        details.push(FsProtocol {
            version: p.version.clone(),
            cipher: p.negotiated_cipher.clone(),
            forward_secret: fs,
        });
    }
    // Vacuously-true `all` over an empty set is misleading; require evidence.
    ForwardSecrecy { all_forward_secret: !details.is_empty() && all, protocols: details }
}

/// Whether a negotiated suite provides forward secrecy. TLS 1.3 mandates
/// ephemeral (EC)DHE for every suite; TLS 1.2 is forward-secret only with an
/// ephemeral key exchange, identifiable by `ECDHE`/`DHE` in the suite name.
fn is_forward_secret(version: &str, cipher: Option<&str>) -> bool {
    if version.starts_with("TLS 1.3") {
        return true;
    }
    match cipher {
        Some(name) => name.contains("ECDHE") || name.contains("DHE"),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto(version: &str, supported: bool, cipher: Option<&str>) -> ProtocolResult {
        ProtocolResult {
            version: version.to_string(),
            supported,
            negotiated_cipher: cipher.map(str::to_string),
            negotiated_group: None,
        }
    }

    #[test]
    fn tls13_is_always_forward_secret() {
        assert!(is_forward_secret("TLS 1.3", None));
        assert!(is_forward_secret("TLS 1.3", Some("TLS13_AES_256_GCM_SHA384")));
    }

    #[test]
    fn tls12_forward_secrecy_keys_off_suite_name() {
        assert!(is_forward_secret(
            "TLS 1.2",
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        ));
        assert!(is_forward_secret(
            "TLS 1.2",
            Some("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256")
        ));
        assert!(!is_forward_secret(
            "TLS 1.2",
            Some("TLS_RSA_WITH_AES_128_GCM_SHA256")
        ));
        assert!(!is_forward_secret("TLS 1.2", None));
    }

    #[test]
    fn forward_secrecy_ignores_unsupported_protocols() {
        let protocols = [
            proto("TLS 1.2", false, None),
            proto("TLS 1.3", true, Some("TLS13_AES_256_GCM_SHA384")),
        ];
        let fs = forward_secrecy(&protocols);
        assert!(fs.all_forward_secret);
        assert_eq!(fs.protocols.len(), 1);
        assert_eq!(fs.protocols[0].version, "TLS 1.3");
    }

    #[test]
    fn forward_secrecy_flags_non_fs_suite() {
        let protocols = [proto("TLS 1.2", true, Some("TLS_RSA_WITH_AES_128_GCM_SHA256"))];
        assert!(!forward_secrecy(&protocols).all_forward_secret);
    }

    #[test]
    fn forward_secrecy_empty_is_not_vacuously_true() {
        assert!(!forward_secrecy(&[]).all_forward_secret);
        assert!(!forward_secrecy(&[proto("TLS 1.2", false, None)]).all_forward_secret);
    }

    #[test]
    fn hsts_absent_header() {
        let h = parse_hsts(None);
        assert!(!h.present);
        assert_eq!(h.max_age, None);
        assert!(!h.include_subdomains);
        assert!(!h.preload);
    }

    #[test]
    fn hsts_full_directive_set() {
        let h = parse_hsts(Some("max-age=31536000; includeSubDomains; preload"));
        assert!(h.present);
        assert_eq!(h.max_age, Some(31_536_000));
        assert!(h.include_subdomains);
        assert!(h.preload);
    }

    #[test]
    fn hsts_max_age_only_case_insensitive() {
        let h = parse_hsts(Some("Max-Age=600"));
        assert_eq!(h.max_age, Some(600));
        assert!(!h.include_subdomains);
        assert!(!h.preload);
    }

    #[test]
    fn hsts_quoted_and_spaced_max_age() {
        let h = parse_hsts(Some("max-age=\"7776000\" ; IncludeSubDomains"));
        assert_eq!(h.max_age, Some(7_776_000));
        assert!(h.include_subdomains);
    }

    #[test]
    fn hsts_malformed_max_age_is_none_but_present() {
        let h = parse_hsts(Some("max-age=oops; preload"));
        assert!(h.present);
        assert_eq!(h.max_age, None);
        assert!(h.preload);
    }

    #[test]
    fn sni_ip_target_is_not_applicable() {
        let b = classify_sni("192.0.2.1", None, &NoSni::Rejected);
        assert_eq!(b.outcome, "not-applicable");
    }

    #[test]
    fn sni_rejected_without_sni() {
        let b = classify_sni("example.com", Some(b"leaf-der"), &NoSni::Rejected);
        assert_eq!(b.outcome, "rejected-without-sni");
    }

    #[test]
    fn sni_unavailable_when_unresolved() {
        let b = classify_sni("example.com", Some(b"leaf-der"), &NoSni::Unavailable);
        assert_eq!(b.outcome, "unknown");
    }

    #[test]
    fn sni_same_and_different_certificate() {
        let leaf = b"identical-der".to_vec();
        let same = classify_sni("example.com", Some(&leaf), &NoSni::Leaf(leaf.clone()));
        assert_eq!(same.outcome, "same-certificate");

        let diff = classify_sni("example.com", Some(b"sni-der"), &NoSni::Leaf(b"default-der".to_vec()));
        assert_eq!(diff.outcome, "different-certificate");
    }
}
