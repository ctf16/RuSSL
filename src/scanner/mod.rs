pub mod cert;
pub mod ciphers;
pub mod handshake;
pub mod vulns;

use anyhow::Result;
use serde::Serialize;

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

#[allow(dead_code)] // timeout_secs wired to CLI; enforcement added in Phase 2
pub struct ScanOpts {
    pub enumerate_ciphers: bool,
    pub check_vulns: bool,
    pub timeout_secs: u64,
}

#[derive(Serialize, Debug)]
pub struct ScanResult {
    pub host: String,
    pub port: u16,
    pub certificate: cert::CertInfo,
    pub protocols: Vec<handshake::ProtocolResult>,
    pub cipher_suites: Vec<ciphers::CipherResult>,
    pub vulnerabilities: Vec<vulns::VulnResult>,
}

pub async fn run_scan(target: &Target, opts: &ScanOpts) -> Result<ScanResult> {
    eprintln!("Scanning {}:{}...\n", target.host, target.port);

    let certificate = cert::inspect(target).await?;
    let protocols = handshake::probe_protocols(target).await?;

    let cipher_suites = if opts.enumerate_ciphers {
        ciphers::enumerate(target).await?
    } else {
        vec![]
    };

    let vulnerabilities = if opts.check_vulns {
        vulns::check_all(target, &protocols).await?
    } else {
        vec![]
    };

    Ok(ScanResult {
        host: target.host.clone(),
        port: target.port,
        certificate,
        protocols,
        cipher_suites,
        vulnerabilities,
    })
}
