# RuSSL
RuSSL is a Rust async CLI tool that connects to a remote host, performs TLS
handshakes, parses the certificate chain, optionally probes cipher suite
acceptance, and optionally runs inference-based vulnerability checks.


Output is either a formatted table (default) or machine-readable JSON (`--json`).

## Requirements

- Rust 1.75+ (2021 edition)
- No external services or environment variables required

## Install

Clone and build with Cargo:

```sh
git clone https://github.com/ctf16/RuSSL.git
cd russl
cargo build --release
```

The compiled binary will be at `target/release/russl`.

Alternatively, run directly without installing:

```sh
cargo run -- <args>
```

## Usage

```
russl [OPTIONS] <HOST>

Arguments:
  <HOST>  Target hostname

Options:
  -p, --port <PORT>       Target port [default: 443]
      --enumerate-ciphers Enumerate supported cipher suites
      --check-vulns       Run vulnerability checks
      --json              Output results as JSON
      --timeout <SECS>    Connection timeout in seconds [default: 10]
  -h, --help              Print help
```

### Examples

Basic certificate and protocol inspection:

```sh
russl example.com
```

Include cipher suite enumeration and vulnerability checks:

```sh
russl example.com --enumerate-ciphers --check-vulns
```

Custom port with JSON output (pipeable):

```sh
russl example.com --port 8443 --json
```

Non-standard port with all checks:

```sh
russl example.com --port 8443 --enumerate-ciphers --check-vulns --json
```

## Features

### Certificate inspection (always on)

- Subject and issuer distinguished names
- Validity window (Not Before / Not After)
- Days remaining until expiry, expired flag
- Public key algorithm and signature algorithm
- Certificate chain depth
- Subject Alternative Names (SANs)

### Protocol support probing (always on)

Probes TLS 1.0, TLS 1.1, TLS 1.2, and TLS 1.3 via independent handshakes and
reports which versions the server accepts.

### Cipher suite enumeration (`--enumerate-ciphers`)

Probes each known cipher suite individually and reports whether the server
accepted it, along with a strength classification (e.g. Strong, Weak,
Insecure).

### Vulnerability checks (`--check-vulns`)

Inference-based checks against the collected protocol data:

| Check | Method |
|---|---|
| POODLE | Inferred — SSLv3 not probeable via rustls; treated as not supported |
| BEAST | Inferred — flags servers that accept TLS 1.0 (CBC cipher exposure) |
| Deprecated TLS 1.1 | Flags servers that accept TLS 1.1 (RFC 8996) |
| Heartbleed (CVE-2014-0160) | Not yet implemented; placeholder only |

> **Note:** Heartbleed detection requires a raw TCP probe that is not yet
> implemented. Use [testssl.sh](https://testssl.sh) to verify Heartbleed
> status in the meantime.

### Output formats

- **Table** (default) — human-readable, aligned tables rendered with Unicode box
  drawing characters
- **JSON** (`--json`) — machine-readable, pretty-printed JSON written to stdout;
  progress messages go to stderr so the output is cleanly pipeable
