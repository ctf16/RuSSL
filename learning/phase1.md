# Phase 1 — Foundation & Certificate Quality: Theory Notes

Network-security fundamentals behind the checks implemented in Phase 1. Each
section maps to code in `src/scanner/` so the theory stays grounded in what the
tool actually does.

---

## 0. Foundation: why robustness *is* a security property

Before any certificate logic, Phase 1 hardened two boring-but-load-bearing
things (`error.rs`, `scanner::with_timeout`):

- **Typed errors over `anyhow`.** A scanner that swallows the *reason* a
  handshake failed can't distinguish "host refused TLS 1.0" from "DNS failed"
  from "cert parse blew up." Precise error types keep findings honest — a
  network error must never be silently reported as a clean result.
- **Timeouts on every network op.** An attacker (or a flaky host) that never
  finishes a handshake can hang a scanner indefinitely. Bounding every
  `connect`/`read` with `tokio::time::timeout` turns an unbounded wait into a
  defined `Timeout` outcome. Resource-exhaustion resistance is a security
  requirement, not a nicety.

---

## 1. X.509 certificates and the chain of trust

A TLS server proves its identity with an **X.509 certificate** — a signed
binding between a *public key* and an *identity* (domain names). Trust is
transitive:

```
root CA  ──signs──▶  intermediate CA  ──signs──▶  leaf (server) cert
(in OS trust store)   (sent by server)            (sent by server)
```

- The **leaf** carries the server's public key and its names.
- **Intermediates** chain the leaf up toward a root. The server sends leaf +
  intermediates; the client already trusts the root.
- `chain_depth` in `CertInfo` is just how many certs the server presented.

**Encoding — DER/ASN.1.** Certificates are serialized as **DER** (Distinguished
Encoding Rules) of an **ASN.1** structure. DER is a *Type-Length-Value* (TLV)
format: every field is a tag byte, a length, then the contents. `scanner::der`
implements exactly this — a minimal TLV reader/writer — which is also what makes
OCSP (below) possible without a heavyweight ASN.1 library.

**What the tool reads from the leaf** (`cert::inspect` via `x509-parser`):
- **Subject / Issuer** — Distinguished Names (DNs). Subject = who this cert is
  for; Issuer = the CA that signed it.
- **Subject Alternative Names (SANs)** — the DNS names / IPs the cert is valid
  for. Modern clients ignore the legacy CN field and validate against SANs.
- **Validity window** — `notBefore` / `notAfter`. Expiry (`days_remaining`,
  `is_expired`) is the single most common real-world TLS outage.

> **Deliberate design choice:** `cert::CertCapture` is a `ServerCertVerifier`
> with *no-op* signature checks. We capture the raw chain from *any* host,
> including expired or self-signed ones, because inspecting broken certs is the
> whole point. This is the opposite of what a browser does, and it's why the
> tool's HTTPS client (`scanner::http`) uses a *separate*, fully-verifying
> config.

---

## 2. Key strength: how much security does the public key buy?

A certificate's protection is capped by the strength of its key. Different
algorithms need very different key sizes for the same security level, measured
in **bits of security** (work ≈ 2^n to break). Rough equivalences (NIST SP
800-57):

| Algorithm | Key size | ≈ security |
|---|---|---|
| RSA / DSA | 1024-bit | ~80 bits (broken-ish) |
| RSA / DSA | 2048-bit | ~112 bits (current floor) |
| RSA | 3072-bit | ~128 bits |
| EC (P-256) | 256-bit | ~128 bits |
| EC (P-384) | 384-bit | ~192 bits |

This is why `is_weak_key` flags **RSA/DSA < 2048** and **EC < 256**: below those,
the key is the weakest link. Note the asymmetry — a 256-bit *EC* key is strong,
while a 256-bit *RSA* key would be trivially broken. Security level depends on
the math (integer factorization vs. elliptic-curve discrete log), not the raw
bit count, which is why the check branches on algorithm.

Modern EdDSA/X25519 keys (~256-bit, ~128-bit security) are correctly treated as
*not* weak.

---

## 3. Signature algorithms

The CA signs the leaf with a hash-then-sign algorithm (e.g.
`sha256WithRSAEncryption`, `ecdsa-with-SHA256`). The hash matters:
- **SHA-1** signatures (`sha1WithRSAEncryption`) are deprecated — SHA-1 has
  practical collision attacks (SHAttered, 2017), which can in principle forge a
  certificate. CAs stopped issuing SHA-1 certs in 2016.
- SHA-256 and above are current.

`cert::oid_name` maps the raw signature OID to a readable name so the report
shows *what* signed the cert, not a dotted-number string.

---

## 4. Validation levels: DV / OV / EV

CAs issue certificates at different **assurance levels** depending on how much
they verified about the requester:

- **DV (Domain Validated)** — proves only control of the domain (e.g. an ACME
  challenge). Fast, free, automatable (Let's Encrypt). *Says nothing about who
  runs the site.*
- **OV (Organization Validated)** — CA also verified the legal organization.
- **EV (Extended Validation)** — strictest vetting of the legal entity.

These are signaled by **certificate-policy OIDs** under the CA/Browser Forum's
reserved arc `2.23.140.1`:

| OID | Level |
|---|---|
| `2.23.140.1.1` | EV |
| `2.23.140.1.2.1` | DV |
| `2.23.140.1.2.2` | OV |
| `2.23.140.1.2.3` | IV (Individual) |

`classify_validation` reads the `CertificatePolicies` extension and matches
these. When no standardized OID is present, it falls back to a heuristic
(organization present in subject ⇒ likely OV). *Caveat:* the security value of
EV is debated — browsers removed the EV "green bar" because users never relied
on it, so treat the level as informational, not a trust score.

---

## 5. Revocation: OCSP (RFC 6960)

Certificates are valid until they expire — but keys get compromised, so CAs need
a way to say "revoke this one early." Two mechanisms:

- **CRL** (Certificate Revocation List) — a CA-signed list of revoked serials.
  Large, cached, slow to propagate.
- **OCSP** (Online Certificate Status Protocol) — ask the CA about *one* cert,
  on demand. This is what `scanner::ocsp` implements.

**How the check works:**
1. **Find the responder.** The leaf's **Authority Information Access (AIA)**
   extension names an OCSP responder URL under access-method
   `id-ad-ocsp` (`1.3.6.1.5.5.7.48.1`).
2. **Build the request — the `CertID`.** OCSP identifies a cert *without sending
   it*, via three values (RFC 6960 mandates SHA-1 here purely for
   interoperability, not security):
   - `issuerNameHash` — hash of the issuer's DN,
   - `issuerKeyHash` — hash of the issuer's public key,
   - `serialNumber` — the leaf's serial.
   Hashing the issuer name + key (rather than naming it) lets one responder
   serve many CAs unambiguously. `der.rs` hand-encodes this request.
3. **POST it** to the responder. OCSP runs over **plain HTTP** — the response is
   itself CA-signed, so it doesn't need TLS, which is why no extra TLS backend
   is pulled in.
4. **Read the `certStatus`:** `good` / `revoked` / `unknown`.

**Soft-fail.** If the responder is down or returns garbage, the tool reports a
descriptive status instead of failing the scan. This mirrors how *browsers*
behave ("soft-fail") — and is also OCSP's central weakness: an attacker who can
block the OCSP request can suppress a "revoked" answer. (The intended fix,
**OCSP stapling**, is a Phase 2 topic.)

---

## 6. Certificate Transparency (RFC 6962)

Revocation answers "is this cert still valid?" CT answers a different question:
**"was this cert supposed to exist at all?"**

The problem CT solves is **misissuance** — a CA (compromised, coerced, or buggy)
issuing a cert for a domain it shouldn't (e.g. the 2011 DigiNotar breach issued
a wildcard for `*.google.com`). Before CT, such a cert could be used in
targeted attacks invisibly.

**How CT works:**
- Every issued cert is logged to public, **append-only Merkle-tree logs** run by
  multiple independent operators. Append-only + cryptographic tree structure
  means a log can't quietly remove or backdate an entry without detection.
- The log returns a **Signed Certificate Timestamp (SCT)**, a promise to log the
  cert. Browsers (Chrome since 2018, others since) **require** SCTs and reject
  certs without them.
- **Monitors** watch the logs; a domain owner can see *every* cert issued for
  their name and spot rogue issuance.

**What this tool does:** `scanner::ct` queries **crt.sh** (a public CT-log
aggregator/search front-end) over the verifying HTTPS stack and reports how many
log entries exist for the domain. A healthy public domain has many; zero or a
failed lookup is informational (crt.sh is frequently slow or returns 502 — an
external condition the tool degrades on rather than failing).

> CT turns the CA trust model from "trust every CA absolutely" into "trust, but
> everything is publicly auditable."

---

## Key takeaways

- A TLS cert is a **signed key↔identity binding**; trust flows from a root you
  already trust down through intermediates to the leaf.
- Security is bounded by the **weakest** of: key strength, signature hash, and
  the integrity of the issuance process.
- **Three independent questions**, three mechanisms:
  - *Is the binding cryptographically sound right now?* → key/sig/validity
    checks.
  - *Was it revoked early?* → **OCSP**.
  - *Should it ever have existed?* → **Certificate Transparency**.
- Real protocols **fail soft** and degrade gracefully; the tool mirrors that,
  but is careful never to dress a failure up as a clean pass.
