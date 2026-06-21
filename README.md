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
cd RuSSL
cargo build --release
```

The compiled binary will be at `target/release/russl`.

Alternatively, run directly without installing:

```sh
cargo run -- <args>
```

### Docker

A minimal container image is provided via the repository `Dockerfile`. Build it
and invoke `russl` as the image entrypoint:

```sh
docker build -t russl .
docker run --rm russl example.com --connection
docker run --rm russl example.com --json > report.json
```

The image is a statically linked `musl` binary on top of `alpine`, runs as a
non-root user, and bundles `ca-certificates` so the HTTPS-based checks
(`--ocsp`, `--ct`, `--connection`) can verify certificate chains against the
system trust store.

## Usage

```
russl [OPTIONS] <HOST>

Arguments:
  <HOST>  Target hostname

Options:
  -p, --port <PORT>       Target port [default: 443]
      --enumerate-ciphers Enumerate supported cipher suites
      --check-vulns       Run vulnerability checks
      --ocsp              Check certificate revocation status via OCSP
      --ct                Query crt.sh for Certificate Transparency log entries
      --connection        Inspect connection properties (FS, OCSP stapling, resumption, SNI, HSTS)
      --all               Run all available analyses (ciphers, vulns, OCSP, CT, connection)
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
- Public key algorithm, key size in bits, and a weak-key warning
  (RSA < 2048-bit or EC < 256-bit)
- Validation level (EV / OV / DV) from CA/Browser Forum policy OIDs, with a
  subject-based fallback when no standardized policy OID is present
- Signature algorithm
- Certificate chain depth
- Subject Alternative Names (SANs)

### OCSP revocation (`--ocsp`)

Extracts the OCSP responder URL from the certificate's Authority Information
Access extension, POSTs a DER-encoded OCSP request, and reports `Good`,
`Revoked`, or `Unknown`. Certificates without an OCSP responder (e.g. recent
Let's Encrypt) are reported as such rather than treated as an error.

### Certificate Transparency (`--ct`)

Queries [crt.sh](https://crt.sh) for the target domain and reports the number
of Certificate Transparency log entries found. Uses the same tokio-rustls/ring
HTTPS stack as the rest of the tool, so no additional TLS backend is pulled in.

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

### Connection properties (`--connection`)

Describes how the negotiated TLS connection is configured:

| Property | Method |
|---|---|
| Forward secrecy | Whether each negotiated suite uses ephemeral key exchange (TLS 1.3 always; TLS 1.2 via ECDHE/DHE) |
| OCSP stapling | Whether the server stapled an OCSP response into the handshake |
| Session resumption | Whether the server issues TLS 1.3 tickets or a resumable TLS 1.2 session |
| SNI behaviour | Compares the certificate served with SNI against the one served without it (presents an IP `ServerName`); reports same / different / rejected |
| HSTS | HTTPS GET on the target port; reports `max-age`, `includeSubDomains`, `preload` from the `Strict-Transport-Security` header |

### Output formats

- **Table** (default) — human-readable, aligned tables rendered with Unicode box
  drawing characters
- **JSON** (`--json`) — machine-readable, pretty-printed JSON written to stdout;
  progress messages go to stderr so the output is cleanly pipeable
