//! Minimal HTTP/1.1 client built on the project's tokio-rustls/ring stack.
//!
//! Deliberately small: one request/response round-trip per call using
//! `Connection: close`, so the body is delimited by EOF (or chunked decoding
//! when the server insists). This avoids pulling in `reqwest` and a second TLS
//! backend (`aws-lc-rs`), keeping the whole binary on `ring`.

use crate::error::ScanError;
use std::io::Write as _;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

#[derive(Clone, Copy)]
pub enum Scheme {
    Http,
    Https,
}

pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Perform a single HTTP request and read the full response.
///
/// Unlike the certificate-capture path, HTTPS here performs real chain
/// validation against the native root store — these are ordinary client
/// requests to OCSP responders and crt.sh, not inspection targets.
pub async fn request(
    scheme: Scheme,
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Result<HttpResponse, ScanError> {
    let mut req: Vec<u8> = Vec::new();
    // Writing into a Vec via io::Write is infallible.
    let _ = write!(req, "{method} {path} HTTP/1.1\r\n");
    let _ = write!(req, "Host: {host}\r\n");
    let _ = write!(req, "User-Agent: russl/0.1\r\n");
    let _ = write!(req, "Connection: close\r\n");
    for (k, v) in extra_headers {
        let _ = write!(req, "{k}: {v}\r\n");
    }
    if let Some(b) = body {
        let _ = write!(req, "Content-Length: {}\r\n", b.len());
    }
    req.extend_from_slice(b"\r\n");
    if let Some(b) = body {
        req.extend_from_slice(b);
    }

    let tcp = TcpStream::connect((host, port)).await?;

    let raw = match scheme {
        Scheme::Http => {
            let mut stream = tcp;
            stream.write_all(&req).await?;
            stream.flush().await?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await?;
            buf
        }
        Scheme::Https => {
            let connector = TlsConnector::from(https_config());
            let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
                .map_err(|e| ScanError::InvalidName(e.to_string()))?;
            let mut stream = connector.connect(server_name, tcp).await?;
            stream.write_all(&req).await?;
            stream.flush().await?;
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await?;
            buf
        }
    };

    parse_response(&raw)
}

/// Build a verifying client config on the default (ring) provider.
fn https_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
        let _ = roots.add(cert);
    }
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

fn parse_response(raw: &[u8]) -> Result<HttpResponse, ScanError> {
    let split = find_subsequence(raw, b"\r\n\r\n")
        .ok_or_else(|| ScanError::Http("response missing header terminator".into()))?;
    let header_bytes = &raw[..split];
    let body = &raw[split + 4..];

    let headers = String::from_utf8_lossy(header_bytes);
    let mut lines = headers.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| ScanError::Http("empty response".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ScanError::Http(format!("bad status line: {status_line}")))?;

    let mut chunked = false;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("transfer-encoding")
                && v.split(',').any(|t| t.trim().eq_ignore_ascii_case("chunked"))
            {
                chunked = true;
            }
        }
    }

    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };

    Ok(HttpResponse { status, body })
}

/// Decode HTTP/1.1 chunked transfer-encoding. Trailers are ignored.
fn decode_chunked(mut data: &[u8]) -> Result<Vec<u8>, ScanError> {
    let mut out = Vec::new();
    loop {
        let nl = find_subsequence(data, b"\r\n")
            .ok_or_else(|| ScanError::Http("malformed chunk header".into()))?;
        let size_line = std::str::from_utf8(&data[..nl])
            .map_err(|_| ScanError::Http("non-utf8 chunk size".into()))?;
        // A chunk size may carry ";ext" extensions which we discard.
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| ScanError::Http(format!("bad chunk size: {size_hex}")))?;
        data = &data[nl + 2..];
        if size == 0 {
            break;
        }
        if data.len() < size {
            return Err(ScanError::Http("truncated chunk body".into()));
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        // Each chunk is followed by CRLF.
        if data.len() >= 2 {
            data = &data[2..];
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_content_length_body() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello");
    }

    #[test]
    fn decodes_chunked_body() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"Wikipedia");
    }

    #[test]
    fn surfaces_non_200_status() {
        let raw = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_response(raw).unwrap();
        assert_eq!(resp.status, 404);
        assert!(resp.body.is_empty());
    }
}
