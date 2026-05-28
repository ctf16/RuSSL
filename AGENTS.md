# AGENTS.md

Guidance for AI agents working in this repository.

## What this is

**RuSSL** (`tls-inspector` binary/package) is a Rust async CLI tool that connects
to a remote host, performs TLS handshakes, parses the certificate chain, optionally
probes cipher suite acceptance, and optionally runs inference-based vulnerability
checks. Output is either a pretty-printed table (default) or machine-readable JSON
(`--json`).

## Build and run

```sh
cargo build
cargo run -- <host> [--port 443] [--enumerate-ciphers] [--check-vulns] [--json]
```

No environment variables or external services are required.

## Module map

```
src/
  main.rs               CLI parsing (clap derive), CryptoProvider init, dispatch
  error.rs              ScanError enum (thiserror) — reserved for Phase 2 typed errors
  scanner/
    mod.rs              Target, ScanOpts, ScanResult, run_scan() orchestrator
    cert.rs             DER capture via custom ServerCertVerifier, x509-parser decode
    handshake.rs        Per-version TLS handshake probes, attempt_handshake()
    ciphers.rs          Per-suite probes via custom CryptoProvider, semaphore-limited
    vulns.rs            Inference-based vulnerability checks against ProtocolResult slice
  output/
    mod.rs              Re-exports json and pretty submodules
    json.rs             serde_json pretty-print to stdout
    pretty.rs           comfy-table formatted report to stdout
```

## Key architectural decisions

**CryptoProvider must be installed at startup.**
rustls 0.23 does not auto-select a provider when multiple backends are present as
transitive dependencies. `main` calls
`rustls::crypto::ring::default_provider().install_default()` before any TLS work.
All code assumes ring. Do not add `aws-lc-rs` as a direct or indirect dependency
without revisiting this.

**rustls 0.23 builder state machine.**
`ClientConfig::builder()` starts in `WantsVerifier` state — `with_protocol_versions`
is not available on it. Use `builder_with_protocol_versions(versions)` to restrict
versions, or `builder_with_provider(Arc::new(provider))` (→ `WantsVersions`) when
you also need to restrict cipher suites. The two paths are distinct and cannot be
composed after the fact.

**Cipher suite restriction uses CryptoProvider, not builder methods.**
`with_cipher_suites()` was removed in 0.23. To probe a single suite, construct:
```rust
CryptoProvider { cipher_suites: vec![suite], ..ring::default_provider() }
```
and pass it to `builder_with_provider`.

**Certificate capture bypasses chain validation intentionally.**
`cert::CertCapture` implements `ServerCertVerifier` with no-op signature checks so
it can collect the raw DER chain from any host regardless of cert validity. This is
deliberate — inspection of expired or self-signed certs is an explicit use case.

**Progress output goes to stderr.**
`run_scan` uses `eprintln!` for the "Scanning …" banner so that `--json` stdout is
clean and pipeable without stripping a header line.

**OID display.**
`cert::oid_name()` maps dotted OID strings to human-readable names. x509-parser
returns raw OIDs; add new entries there when new key or signature algorithms appear
in the wild rather than touching the output layer.

## rustls-native-certs 0.7 API

`load_native_certs()` returns `Result<Vec<CertificateDer<'static>>, Error>`.
Call `.unwrap_or_default()` to get an empty vec on failure rather than aborting.
The 0.8 API changed this to a struct with a `.certs` field — do not use that form.

## x509-parser 0.16 notes

`ASN1Time::to_datetime()` returns `time::OffsetDateTime`.
Use `.unix_timestamp()` for epoch seconds, not `.timestamp()` (that does not exist
on this type). `chrono::Utc::now().timestamp()` is still correct on the chrono side.

## Phase 2+ work (not yet implemented)

- **Legacy protocol detection** — shell out to `openssl s_client -tls1 / -tls1_1 / -ssl3`
- **Heartbleed raw probe** — manual TLS ClientHello over `TcpStream`, malformed
  HeartbeatRequest (type `0x18`), check for data in response
- **HSTS check** — HTTP GET on port 80, inspect `Strict-Transport-Security` header
- **Bulk scanning** — `--input-file` flag, `FuturesUnordered` pool with configurable
  concurrency
- **CT log check** — query `https://crt.sh/?q=<domain>&output=json`
- **Timeout enforcement** — `ScanOpts::timeout_secs` is wired through from the CLI
  but not yet applied; wrap network calls in `tokio::time::timeout`
- **Typed errors** — `ScanError` in `error.rs` exists but call sites currently use
  `anyhow`; migrate when the public API stabilizes
