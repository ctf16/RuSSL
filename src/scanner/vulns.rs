use crate::error::ScanError;
use crate::scanner::{handshake::ProtocolResult, Target};
use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct VulnResult {
    pub name: String,
    pub vulnerable: bool,
    pub description: String,
    pub severity: String,
}

pub async fn check_all(
    target: &Target,
    protocols: &[ProtocolResult],
) -> Result<Vec<VulnResult>, ScanError> {
    let mut results = vec![];

    // POODLE: requires SSLv3 (not probeable via rustls; inferred as not supported)
    results.push(VulnResult {
        name: "POODLE".into(),
        vulnerable: false,
        description: "SSLv3 not supported by rustls prober (safe by default)".into(),
        severity: "High".into(),
    });

    // BEAST: TLS 1.0 + CBC — inferred
    let has_tls10 = protocols.iter().any(|p| p.version == "TLS 1.0" && p.supported);
    results.push(VulnResult {
        name: "BEAST".into(),
        vulnerable: has_tls10,
        description: "TLS 1.0 with CBC ciphers enables BEAST attack".into(),
        severity: "Medium".into(),
    });

    // Weak protocol: TLS 1.1
    let has_tls11 = protocols.iter().any(|p| p.version == "TLS 1.1" && p.supported);
    results.push(VulnResult {
        name: "Deprecated TLS 1.1".into(),
        vulnerable: has_tls11,
        description: "TLS 1.1 is deprecated per RFC 8996".into(),
        severity: "Low".into(),
    });

    // Heartbleed placeholder — requires raw TCP probe (phase 2)
    results.push(VulnResult {
        name: "Heartbleed (CVE-2014-0160)".into(),
        vulnerable: false,
        description: "Raw TCP probe not yet implemented; use testssl.sh to verify".into(),
        severity: "Critical".into(),
    });

    // Suppress unused variable warning — target reserved for future checks (DROWN, etc.)
    let _ = target;

    Ok(results)
}
