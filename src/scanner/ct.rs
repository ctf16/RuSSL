//! Certificate Transparency lookup via crt.sh.
//!
//! Queries `https://crt.sh/?q=<domain>&output=json` over the project's
//! ring-backed HTTPS client and reports the number of CT log entries crt.sh
//! has indexed for the domain.

use crate::error::ScanError;
use crate::scanner::http::{self, Scheme};
use crate::scanner::with_timeout;

/// Return the count of CT log entries crt.sh reports for `domain`.
pub async fn entry_count(domain: &str, timeout_secs: u64) -> Result<usize, ScanError> {
    let path = format!("/?q={domain}&output=json");

    let response = with_timeout(
        timeout_secs,
        http::request(
            Scheme::Https,
            "crt.sh",
            443,
            "GET",
            &path,
            &[("Accept", "application/json")],
            None,
        ),
    )
    .await?;

    if response.status != 200 {
        return Err(ScanError::Http(format!(
            "crt.sh returned HTTP {}",
            response.status
        )));
    }

    count_entries(&response.body)
}

/// Parse a crt.sh `output=json` body into an entry count.
///
/// crt.sh emits a JSON array of certificate records; the entry count is its
/// length. An all-whitespace/empty body means no logged certificates.
fn count_entries(body: &[u8]) -> Result<usize, ScanError> {
    if body.iter().all(|b| b.is_ascii_whitespace()) {
        return Ok(0);
    }
    let entries: Vec<serde_json::Value> = serde_json::from_slice(body)?;
    Ok(entries.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_json_array_entries() {
        let body = br#"[{"id":1,"name_value":"a.example.com"},
                        {"id":2,"name_value":"b.example.com"},
                        {"id":3,"name_value":"c.example.com"}]"#;
        assert_eq!(count_entries(body).unwrap(), 3);
    }

    #[test]
    fn empty_body_is_zero() {
        assert_eq!(count_entries(b"").unwrap(), 0);
        assert_eq!(count_entries(b"   \n  ").unwrap(), 0);
        assert_eq!(count_entries(b"[]").unwrap(), 0);
    }

    #[test]
    fn malformed_json_errors() {
        assert!(count_entries(b"not json").is_err());
    }

    /// Live HTTPS round-trip through the ring stack. Ignored by default since
    /// it depends on crt.sh availability; run with `--ignored`.
    #[tokio::test]
    #[ignore]
    async fn live_crt_sh_lookup() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let count = entry_count("rust-lang.org", 60).await.unwrap();
        assert!(count > 0, "expected at least one CT entry");
    }
}
