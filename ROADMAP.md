# RuSSL Roadmap

Features are organized into phases, each completing one logical area before the next begins.
Check items off as they are implemented.

---

## Phase 1 — Foundation + Certificate Quality

Infrastructure hardening alongside the first real feature category.

### Foundation

- [ ] Migrate `anyhow` call sites to the typed `ScanError` enum (`error.rs` is already scaffolded)
- [ ] Enforce `timeout_secs` that is already wired through `ScanOpts` — wrap each network call in `tokio::time::timeout`

### Certificate quality checks

- [ ] **Key strength warning** — flag RSA < 2048-bit or EC < 256-bit public keys
- [ ] **OCSP revocation** — extract the OCSP responder URL from the cert's Authority Information Access extension, POST a DER-encoded OCSP request, report `Good / Revoked / Unknown`
- [ ] **Certificate Transparency** — query `https://crt.sh/?q=<domain>&output=json` via `reqwest`, report the number of CT log entries found for the domain
- [ ] **EV / DV / OV classification** — detect certificate policy OIDs to distinguish Extended Validation, Organization Validated, and Domain Validated certs

---

## Phase 2 — Connection Properties

Checks that describe how the TLS connection itself is configured, beyond raw protocol version.

- [ ] **HSTS detection** — HTTP GET on port 80, inspect the `Strict-Transport-Security` response header; report max-age and whether `includeSubDomains` / `preload` are set
- [ ] **Forward secrecy** — determine whether the negotiated cipher suite uses an ephemeral key exchange (ECDHE / DHE); flag servers that only offer non-FS suites
- [ ] **OCSP stapling** — detect whether the server includes a stapled OCSP response in the TLS handshake
- [ ] **Session resumption** — detect support for TLS session tickets and session ID resumption
- [ ] **SNI behaviour** — probe the host with and without SNI, report whether the server presents a different certificate or rejects the connection

---

## Phase 3 — Real Vulnerability Probes

Replace inference-based placeholders with actual network probes, all in pure Rust over `tokio::net::TcpStream`.

- [ ] **Heartbleed (CVE-2014-0160)** — raw TCP connection, hand-crafted TLS ClientHello, malformed HeartbeatRequest extension (type `0x18`); flag if the server returns payload data
- [ ] **SWEET32** — flag acceptance of 3DES and other 64-bit block cipher suites detected during cipher enumeration
- [ ] **LOGJAM** — detect acceptance of export-grade DHE cipher suites (512-bit DH); flag if any are accepted
- [ ] **FREAK** — detect acceptance of export-grade RSA cipher suites; flag if any are accepted
- [ ] **RC4** — flag acceptance of any RC4 cipher suite
- [ ] **ROBOT (Bleichenbacher oracle)** — send a series of crafted RSA PKCS#1 v1.5 `ClientKeyExchange` messages over raw TCP and detect timing or error-message differences that indicate the oracle

> **Note:** SSLv3 (POODLE) and SSLv2 (DROWN) require handshake stacks that rustls does not implement. These remain inference-only and cannot be probed in pure Rust without a separate SSLv2/v3 implementation.

---

## Phase 4 — UX and Output

Polish the human-readable experience and add workflow features.

- [ ] **Terminal colour** — highlight expired certs, weak keys, and vulnerable findings in red/yellow using a pure-Rust ANSI colour crate; respect `NO_COLOR` and `--no-color`
- [ ] **Verbosity control** — `--verbose` to include raw field values and extended details; `--quiet` to print only findings that require attention
- [ ] **Output to file** — `--output <path>` writes the report (table or JSON) to a file instead of stdout
- [ ] **Bulk scanning** — `--input-file <path>` accepts a newline-delimited list of `host[:port]` targets; runs scans concurrently via `FuturesUnordered` with a configurable concurrency cap
- [ ] **Scan diffing** — `--diff <previous.json>` compares the current scan result against a saved JSON report and highlights changes (new SANs, expiry delta, newly accepted/rejected ciphers, changed vuln status)
