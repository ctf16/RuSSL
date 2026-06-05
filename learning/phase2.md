# Phase 2 — Connection Properties: Theory Notes

Where Phase 1 asked *"is this certificate any good?"*, Phase 2 asks *"how is the
live TLS connection actually configured?"* — properties that depend on the
handshake and the server's behaviour, not just the cert. Each section maps to a
probe in `src/scanner/connection.rs`.

A recurring theme: every check here exists because a *correct* certificate is
not sufficient. You can have a perfect cert and still be downgradable,
retroactively decryptable, fingerprintable, or replayable.

---

## 1. Forward secrecy: protecting *past* sessions from *future* key theft

The core question: **if the server's long-term private key is stolen tomorrow,
can an attacker decrypt traffic they recorded today?**

It comes down to *how the session key is established* during the handshake:

- **Static RSA key transport** (old TLS ≤1.2, suites like
  `TLS_RSA_WITH_AES_128_GCM_SHA256`): the client picks the pre-master secret,
  encrypts it with the server's RSA *public* key, and sends it. Anyone who later
  obtains the RSA *private* key can decrypt that message — and therefore every
  past session they recorded. **No forward secrecy.**
- **Ephemeral (EC)DHE** (`TLS_ECDHE_*`, `TLS_DHE_*`): client and server run a
  *fresh* Diffie-Hellman exchange per connection. The session key is derived
  from ephemeral DH values that are thrown away after the handshake. The
  long-term key only ever *signs* the exchange (proves identity); it never
  encrypts the session key. Stealing it later authenticates as the server going
  forward, but **cannot retroactively decrypt** recorded sessions.

This is the defence against **"harvest now, decrypt later"** — an adversary who
records ciphertext in bulk and waits years to obtain (or factor) the key.

**TLS 1.3 settles the debate:** it *removed static RSA key transport entirely* —
every 1.3 cipher suite is forward-secret by construction. That's why
`is_forward_secret` returns `true` for any TLS 1.3 connection unconditionally,
and for TLS 1.2 keys off `ECDHE`/`DHE` appearing in the negotiated suite name.

> Implementation note: rustls only ships ephemeral suites even for TLS 1.2, so a
> rustls-negotiated connection is essentially always forward-secret. The check
> still reports it as an observable *property of this connection* rather than an
> assumption.

---

## 2. OCSP stapling: fixing OCSP's privacy and soft-fail holes

Recall Phase 1's OCSP weakness: the *client* contacts the CA's responder to ask
"is this cert revoked?" That has two problems:

1. **Privacy leak** — the CA (and anyone on that network path) learns which
   sites you visit, and *when*.
2. **Soft-fail** — if an attacker blocks the OCSP request, the client gives up
   and proceeds. A "revoked" answer can simply be suppressed.

**OCSP stapling** inverts who fetches the status:

- The *server* periodically asks the CA for a signed, time-stamped OCSP response
  about its own cert, and **staples** (attaches) it directly into the TLS
  handshake.
- The client gets the revocation status for free, from the same connection — no
  third party contacted, nothing for a network attacker to block selectively.
- The stapled response is **CA-signed and short-lived**, so the server can't
  forge or replay an old "good" status indefinitely.

**The handshake mechanics:** the client advertises support with the
`status_request` TLS extension (RFC 6066). If the server stapled a response, it
arrives as a `CertificateStatus` message (TLS 1.2) or inside the certificate
extensions (TLS 1.3), and the TLS stack hands it to the certificate verifier.

**How the tool detects it:** rustls *always* sends `status_request`, so we don't
need to configure anything — `cert::CertCapture` simply records the
`ocsp_response` bytes the verifier receives. Non-empty ⇒ the server staples.

> **OCSP Must-Staple** (RFC 7633) is the endgame: a cert extension telling
> clients "reject me if I'm *not* accompanied by a fresh staple," which finally
> closes the soft-fail hole. Stapling without Must-Staple is an optimization;
> with it, it's an enforced security control.

---

## 3. Session resumption: the cost/security trade-off of skipping the handshake

A full TLS handshake is expensive: multiple round-trips plus asymmetric
crypto (signatures, key exchange). **Resumption** lets a returning client skip
most of that by reusing keying material from a previous session.

Two historical mechanisms (TLS 1.2):

- **Session IDs** — the server caches session state and hands the client an
  opaque ID; on return, the client presents the ID and the server looks it up.
  Stateful (server-side memory).
- **Session Tickets** (RFC 5077) — *stateless*: the server encrypts the session
  state under a **Session Ticket Encryption Key (STEK)** and gives the blob to
  the client to store. On return the client hands it back; the server decrypts
  it. No server-side storage.

**TLS 1.3** unifies this: after the handshake the server sends one or more
`NewSessionTicket` messages, and resumption works via a **pre-shared key (PSK)**
derived from the previous session.

**The security tension:** resumption is in direct tension with forward secrecy.

- The STEK becomes a high-value, long-lived secret. If it isn't **rotated
  frequently**, a stolen STEK decrypts the session state of *many* connections —
  re-introducing exactly the retroactive-decryption risk forward secrecy was
  meant to kill. Correct deployment rotates STEKs on the order of hours.
- **TLS 1.3 0-RTT ("early data")**, built on resumption, lets a client send
  application data in its very first flight. That data is **replayable** by an
  attacker (it isn't tied to a fresh exchange) and isn't forward-secret —
  so it must only carry idempotent requests. (The tool doesn't probe 0-RTT, but
  it's the sharp edge of this feature.)

**How the tool detects support:** `connection.rs` installs a `RecordingStore`
(wrapping rustls's `ClientSessionMemoryCache`) that flips a flag whenever rustls
calls `set_tls12_session` or `insert_tls13_ticket` — i.e. whenever the server
hands us resumable material. One subtlety: TLS 1.2 tickets arrive *during* the
handshake, but the TLS 1.3 `NewSessionTicket` is a *post-handshake* message, so
the probe drives one short, best-effort HTTP round-trip to give it a chance to
arrive.

---

## 4. SNI behaviour: virtual hosting, fingerprinting, and the privacy leak

**Server Name Indication (SNI, RFC 6066)** exists because of a chicken-and-egg
problem: many sites share one IP address, but the server must choose *which
certificate to present* before it knows which site the client wants — and the
HTTP `Host:` header comes *after* the TLS handshake. SNI fixes this by putting
the target hostname in the **ClientHello**, so the server can select the right
virtual host's certificate up front.

The catch: **SNI is sent in cleartext.** Even though the rest of the connection
is encrypted, a network observer sees *which domain* you're connecting to. This
is one of the last metadata leaks in TLS, and the motivation for **Encrypted
Client Hello (ECH)** (the successor to the abandoned ESNI), which encrypts the
ClientHello's sensitive fields.

**What a server does when SNI is absent** is revealing:

- **Same certificate** — the server has a single/default cert; SNI doesn't
  change what it serves.
- **Different certificate** — the server returns a *fallback/default* virtual
  host (e.g. BadSSL's `badssl-fallback-unknown-subdomain-or-no-sni` cert),
  exposing its multi-tenant layout.
- **Rejected** — the server refuses to complete a handshake without SNI.

**How the tool probes it:** rustls omits the SNI extension when the
`ServerName` is an **IP address** rather than a DNS name. So `connection.rs`
resolves the host to an IP, runs a second handshake presenting that IP as the
server name (⇒ no SNI sent), and compares the leaf DER against the normal
SNI handshake. An IP *target* is reported `not-applicable` — neither probe would
carry SNI, so there's nothing to compare.

---

## 5. HSTS: defeating the downgrade / SSL-stripping attack

TLS protects a connection, but the *first* connection is the weak point. A user
types `example.com`; the browser tries `http://example.com` first, and the site
redirects to HTTPS. A **man-in-the-middle** (e.g. on open Wi-Fi) can sit in that
plaintext gap and **SSL-strip**: keep talking HTTPS to the server while serving
plain HTTP to the victim, rewriting `https://` links to `http://`
(Moxie Marlinspike's `sslstrip`, 2009). The user never reaches TLS at all.

**HTTP Strict Transport Security (HSTS, RFC 6797)** closes the gap. The server
sends a response header:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

- **`max-age`** — for this many seconds, the browser will **only** ever use
  HTTPS for this host, upgrading any `http://` attempt *before* a request leaves
  the machine. No plaintext request, nothing to strip.
- **`includeSubDomains`** — apply the policy to every subdomain too.
- **`preload`** — opt into the **HSTS preload list**, a set of domains hardcoded
  into browsers as HTTPS-only out of the box.

The preload list matters because plain HSTS is **trust-on-first-use (TOFU)**:
the very first visit (before any header is seen) is still strippable. Preloading
removes that window by shipping the policy *with the browser*.

**Why it must be read over HTTPS:** per spec, browsers **ignore** an HSTS header
received over plaintext HTTP (otherwise an attacker could inject a bogus one).
The header is only meaningful — and only sent by well-configured servers — over
TLS. That's why the tool's HSTS probe does an **HTTPS GET on the target port**
(via the verifying `scanner::http` client), not a cleartext request to port 80,
and parses `max-age` / `includeSubDomains` / `preload` from the header. A target
that doesn't speak HTTPS there, or has an untrusted cert, yields `hsts: null` —
degraded, not fatal.

---

## Key takeaways

- A valid certificate is **necessary but not sufficient**. Connection properties
  decide whether that cert's protection actually holds up in practice.
- **Forward secrecy** protects the past from future key compromise; TLS 1.3
  makes it mandatory.
- **OCSP stapling** fixes plain OCSP's privacy and soft-fail flaws by moving the
  fetch to the server and binding a signed status into the handshake.
- **Session resumption** trades handshake cost against forward secrecy — safe
  only with disciplined key rotation, and dangerous at the 0-RTT edge.
- **SNI** is a routing necessity that leaks the destination domain in cleartext;
  its no-SNI behaviour fingerprints the server's virtual-host setup.
- **HSTS** defends the plaintext "first hop" against downgrade/stripping, with
  preloading closing the trust-on-first-use gap.
- As in Phase 1, every probe **degrades gracefully** and reports what it
  actually observed — never dressing an unreachable check up as a pass or fail.
