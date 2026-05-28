//! OCSP revocation check (RFC 6960).
//!
//! Builds a DER `OCSPRequest` for the leaf certificate, POSTs it to the
//! responder named in the leaf's Authority Information Access extension (OCSP
//! runs over plain HTTP, so no extra TLS backend is needed), and walks the
//! `OCSPResponse` to extract the single `certStatus`.

use crate::error::ScanError;
use crate::scanner::der;
use crate::scanner::http::{self, Scheme};
use crate::scanner::with_timeout;
use x509_parser::prelude::*;

/// id-ad-ocsp — the AIA access method that names an OCSP responder.
const OID_AD_OCSP: &str = "1.3.6.1.5.5.7.48.1";

/// Run the check and render a human/JSON-friendly status string. Network and
/// parse failures degrade to a descriptive message rather than aborting the
/// whole scan — revocation status is advisory, not fatal.
pub async fn check(certs: &[Vec<u8>], timeout_secs: u64) -> String {
    match query(certs, timeout_secs).await {
        Ok(status) => status,
        Err(e) => format!("Check failed: {e}"),
    }
}

async fn query(certs: &[Vec<u8>], timeout_secs: u64) -> Result<String, ScanError> {
    if certs.len() < 2 {
        return Ok("No issuer certificate in chain".into());
    }

    let (_, leaf) =
        parse_x509_certificate(&certs[0]).map_err(|e| ScanError::CertParse(e.to_string()))?;
    let (_, issuer) =
        parse_x509_certificate(&certs[1]).map_err(|e| ScanError::CertParse(e.to_string()))?;

    let url = match ocsp_url(&leaf) {
        Some(u) => u,
        None => return Ok("No OCSP responder in certificate".into()),
    };

    let request = build_request(&leaf, &issuer);
    let (scheme, host, port, path) = parse_url(&url)?;

    let response = with_timeout(
        timeout_secs,
        http::request(
            scheme,
            &host,
            port,
            "POST",
            &path,
            &[
                ("Content-Type", "application/ocsp-request"),
                ("Accept", "application/ocsp-response"),
            ],
            Some(&request),
        ),
    )
    .await?;

    if response.status != 200 {
        return Ok(format!("Responder returned HTTP {}", response.status));
    }

    Ok(match parse_status(&response.body)? {
        CertStatus::Good => "Good".into(),
        CertStatus::Revoked => "Revoked".into(),
        CertStatus::Unknown => "Unknown".into(),
        CertStatus::ResponderError => "Responder error".into(),
    })
}

/// Extract the first OCSP responder URL from the certificate's AIA extension.
fn ocsp_url(cert: &X509Certificate) -> Option<String> {
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for desc in aia.iter() {
                if desc.access_method.to_string() == OID_AD_OCSP {
                    if let GeneralName::URI(uri) = &desc.access_location {
                        return Some(uri.to_string());
                    }
                }
            }
        }
    }
    None
}

/// Assemble the DER `OCSPRequest` for `leaf` issued by `issuer`.
///
/// `CertID` uses SHA-1 (mandated by RFC 6960 for interoperability): the hash of
/// the issuer's DN, the hash of the issuer's public key bits, and the leaf
/// serial number.
fn build_request(leaf: &X509Certificate, issuer: &X509Certificate) -> Vec<u8> {
    let issuer_name_hash = sha1(leaf.issuer().as_raw());
    let issuer_key_hash = sha1(&issuer.public_key().subject_public_key.data);

    let mut cert_id = Vec::new();
    cert_id.extend_from_slice(&der::ALGID_SHA1);
    cert_id.extend_from_slice(&der::octet_string(issuer_name_hash.as_ref()));
    cert_id.extend_from_slice(&der::octet_string(issuer_key_hash.as_ref()));
    cert_id.extend_from_slice(&der::integer(leaf.raw_serial()));
    let cert_id = der::sequence(&cert_id);

    // Request ::= SEQUENCE { reqCert CertID }
    let request = der::sequence(&cert_id);
    // requestList ::= SEQUENCE OF Request
    let request_list = der::sequence(&request);
    // TBSRequest ::= SEQUENCE { requestList }
    let tbs = der::sequence(&request_list);
    // OCSPRequest ::= SEQUENCE { tbsRequest }
    der::sequence(&tbs)
}

fn sha1(data: &[u8]) -> ring::digest::Digest {
    ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
}

enum CertStatus {
    Good,
    Revoked,
    Unknown,
    /// Responder rejected the request (responseStatus != successful).
    ResponderError,
}

/// Walk an `OCSPResponse` down to the single response's `certStatus` tag.
fn parse_status(der_bytes: &[u8]) -> Result<CertStatus, ScanError> {
    let err = || ScanError::Http("malformed OCSP response".into());

    // OCSPResponse ::= SEQUENCE { responseStatus ENUMERATED, [0] responseBytes }
    let ocsp = der::read_tlv(der_bytes).ok_or_else(err)?;
    let top = der::children(ocsp.content);
    let response_status = top.first().ok_or_else(err)?;
    if response_status.tag != 0x0a || response_status.content.first() != Some(&0) {
        return Ok(CertStatus::ResponderError);
    }

    // [0] EXPLICIT ResponseBytes ::= SEQUENCE { responseType OID, response OCTET STRING }
    let response_bytes_ctx = top.get(1).ok_or_else(err)?;
    let response_bytes = der::read_tlv(response_bytes_ctx.content).ok_or_else(err)?;
    let rb_children = der::children(response_bytes.content);
    let basic_os = rb_children.get(1).ok_or_else(err)?;

    // BasicOCSPResponse ::= SEQUENCE { tbsResponseData, sigAlg, signature, [0] certs }
    let basic = der::read_tlv(basic_os.content).ok_or_else(err)?;
    let basic_children = der::children(basic.content);
    let response_data = basic_children.first().ok_or_else(err)?;

    // ResponseData ::= SEQUENCE { [0] version, responderID, producedAt,
    //                             responses SEQUENCE OF SingleResponse, [1] ext }
    // version is [0] (0xA0), responderID is [1]/[2] (0xA1/0xA2), producedAt is
    // GeneralizedTime (0x18); the responses list is the first plain SEQUENCE.
    let rd_children = der::children(response_data.content);
    let responses = rd_children
        .iter()
        .find(|t| t.tag == 0x30)
        .ok_or_else(err)?;

    let single = der::children(responses.content);
    let single_response = single.first().ok_or_else(err)?;
    let sr_children = der::children(single_response.content);

    // SingleResponse ::= SEQUENCE { certID, certStatus, thisUpdate, ... }
    let cert_status = sr_children.get(1).ok_or_else(err)?;
    Ok(match cert_status.tag {
        0x80 => CertStatus::Good,    // good   [0] IMPLICIT NULL
        0xa1 => CertStatus::Revoked, // revoked [1] IMPLICIT RevokedInfo
        _ => CertStatus::Unknown,    // unknown [2] IMPLICIT UnknownInfo
    })
}

/// Split a responder URL into scheme/host/port/path. Only http(s) is accepted.
fn parse_url(url: &str) -> Result<(Scheme, String, u16, String), ScanError> {
    let (scheme, rest, default_port) = if let Some(r) = url.strip_prefix("http://") {
        (Scheme::Http, r, 80)
    } else if let Some(r) = url.strip_prefix("https://") {
        (Scheme::Https, r, 443)
    } else {
        return Err(ScanError::Http(format!("unsupported OCSP URL: {url}")));
    };

    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    };

    Ok((scheme, host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::der::{octet_string, sequence, tlv};

    /// Build a minimal but structurally valid OCSPResponse carrying the given
    /// `certStatus` tag, exercising the full response walker.
    fn synth_response(cert_status: Vec<u8>) -> Vec<u8> {
        let cert_id = sequence(
            &[
                der::ALGID_SHA1.to_vec(),
                octet_string(&[0xaa; 20]),
                octet_string(&[0xbb; 20]),
                der::integer(&[0x01]),
            ]
            .concat(),
        );
        let this_update = tlv(0x18, b"20240101000000Z");
        let single_response = sequence(&[cert_id, cert_status, this_update].concat());
        let responses = sequence(&single_response);

        let responder_id = tlv(0xA2, &octet_string(&[0xcc; 20])); // byKey [2]
        let produced_at = tlv(0x18, b"20240101000000Z");
        let response_data = sequence(&[responder_id, produced_at, responses].concat());

        let sig_alg = der::ALGID_SHA1.to_vec();
        let signature = tlv(0x03, &[0x00, 0xde, 0xad]); // BIT STRING
        let basic = sequence(&[response_data, sig_alg, signature].concat());

        let oid_basic = tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01]);
        let response_bytes_inner = sequence(&[oid_basic, octet_string(&basic)].concat());
        let response_bytes = tlv(0xA0, &response_bytes_inner);

        let response_status = tlv(0x0a, &[0x00]); // successful
        sequence(&[response_status, response_bytes].concat())
    }

    #[test]
    fn parses_good() {
        let resp = synth_response(vec![0x80, 0x00]);
        assert!(matches!(parse_status(&resp), Ok(CertStatus::Good)));
    }

    #[test]
    fn parses_revoked() {
        // revoked [1] IMPLICIT RevokedInfo { revocationTime GeneralizedTime }
        let revoked = tlv(0xA1, &tlv(0x18, b"20240101000000Z"));
        let resp = synth_response(revoked);
        assert!(matches!(parse_status(&resp), Ok(CertStatus::Revoked)));
    }

    #[test]
    fn parses_unknown() {
        let resp = synth_response(vec![0x82, 0x00]);
        assert!(matches!(parse_status(&resp), Ok(CertStatus::Unknown)));
    }

    #[test]
    fn responder_error_when_status_nonzero() {
        // responseStatus = tryLater (3), no responseBytes
        let resp = sequence(&tlv(0x0a, &[0x03]));
        assert!(matches!(parse_status(&resp), Ok(CertStatus::ResponderError)));
    }

    #[test]
    fn url_parsing() {
        let (_, host, port, path) = parse_url("http://ocsp.example.com/path").unwrap();
        assert_eq!(host, "ocsp.example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/path");

        let (_, host, port, path) = parse_url("http://r3.o.lencr.org").unwrap();
        assert_eq!(host, "r3.o.lencr.org");
        assert_eq!(port, 80);
        assert_eq!(path, "/");

        let (_, host, port, _) = parse_url("https://ocsp.example.com:8443/x").unwrap();
        assert_eq!(host, "ocsp.example.com");
        assert_eq!(port, 8443);

        assert!(parse_url("ftp://nope").is_err());
    }
}
