mod error;
mod output;
mod scanner;

use clap::Parser;
use scanner::{ScanOpts, Target};
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(name = "tls-inspector", about = "TLS stack inspection tool")]
struct Cli {
    /// Target hostname
    host: String,

    /// Target port
    #[arg(short, long, default_value = "443")]
    port: u16,

    /// Output results as JSON
    #[arg(long)]
    json: bool,

    /// Enumerate supported cipher suites
    #[arg(long)]
    enumerate_ciphers: bool,

    /// Run vulnerability checks
    #[arg(long)]
    check_vulns: bool,

    /// Check certificate revocation status via OCSP
    #[arg(long)]
    ocsp: bool,

    /// Query crt.sh for Certificate Transparency log entries
    #[arg(long)]
    ct: bool,

    /// Run all available analyses (implies --enumerate-ciphers --check-vulns --ocsp --ct)
    #[arg(long)]
    all: bool,

    /// Connection timeout in seconds
    #[arg(long, default_value = "10")]
    timeout: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    // rustls 0.23 requires an explicit provider when multiple crypto backends
    // are present as transitive dependencies. Pin to ring throughout.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring CryptoProvider");

    let cli = Cli::parse();

    let target = Target { host: cli.host.clone(), port: cli.port };
    let opts = ScanOpts {
        enumerate_ciphers: cli.enumerate_ciphers || cli.all,
        check_vulns: cli.check_vulns || cli.all,
        check_ocsp: cli.ocsp || cli.all,
        check_ct: cli.ct || cli.all,
        timeout_secs: cli.timeout,
    };

    let result = match scanner::run_scan(&target, &opts).await {
        Ok(result) => result,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let printed = if cli.json {
        output::json::print(&result)
    } else {
        output::pretty::print(&result);
        Ok(())
    };

    if let Err(e) = printed {
        eprintln!("Error: {e}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}
