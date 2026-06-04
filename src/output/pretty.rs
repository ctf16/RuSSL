use crate::scanner::ScanResult;
use comfy_table::{presets::UTF8_FULL, Table};

pub fn print(result: &ScanResult) {
    println!("═══════════════════════════════════════════");
    println!("  TLS Inspection Report: {}:{}", result.host, result.port);
    println!("═══════════════════════════════════════════\n");

    // Certificate
    let c = &result.certificate;
    println!("📜 Certificate");
    let mut t = Table::new();
    t.load_preset(UTF8_FULL);
    t.add_row(vec!["Subject", &c.subject]);
    t.add_row(vec!["Issuer", &c.issuer]);
    t.add_row(vec!["Not Before", &c.not_before]);
    t.add_row(vec!["Not After", &c.not_after]);
    t.add_row(vec!["Days Remaining", &c.days_remaining.to_string()]);
    t.add_row(vec!["Expired", &c.is_expired.to_string()]);
    t.add_row(vec!["Key Algorithm", &c.key_algorithm]);
    let key_size = match c.key_bits {
        Some(bits) if c.weak_key => format!("{bits} bits (WEAK)"),
        Some(bits) => format!("{bits} bits"),
        None => "unknown".to_string(),
    };
    t.add_row(vec!["Key Size", &key_size]);
    t.add_row(vec!["Validation", &c.validation_level]);
    t.add_row(vec!["Sig Algorithm", &c.signature_algorithm]);
    t.add_row(vec!["Chain Depth", &c.chain_depth.to_string()]);
    t.add_row(vec!["SANs", &c.sans.join(", ")]);
    if let Some(status) = &c.ocsp_status {
        t.add_row(vec!["OCSP Status", status]);
    }
    if let Some(count) = c.ct_log_entries {
        let ct = count.to_string();
        t.add_row(vec!["CT Log Entries", &ct]);
    }
    println!("{t}\n");

    // Protocols
    println!("🔒 Protocol Support");
    let mut t = Table::new();
    t.load_preset(UTF8_FULL);
    t.set_header(vec!["Protocol", "Supported", "Negotiated Cipher", "Group"]);
    for p in &result.protocols {
        t.add_row(vec![
            p.version.as_str(),
            if p.supported { "✅ Yes" } else { "❌ No" },
            p.negotiated_cipher.as_deref().unwrap_or("—"),
            p.negotiated_group.as_deref().unwrap_or("—"),
        ]);
    }
    println!("{t}\n");

    // Ciphers
    if !result.cipher_suites.is_empty() {
        println!("🔐 Cipher Suites");
        let mut t = Table::new();
        t.load_preset(UTF8_FULL);
        t.set_header(vec!["Suite", "Accepted", "Strength"]);
        for c in &result.cipher_suites {
            t.add_row(vec![
                c.suite.as_str(),
                if c.accepted { "✅" } else { "❌" },
                c.strength.as_str(),
            ]);
        }
        println!("{t}\n");
    }

    // Connection properties
    if let Some(conn) = &result.connection {
        println!("🔗 Connection Properties");
        let mut t = Table::new();
        t.load_preset(UTF8_FULL);
        t.set_header(vec!["Property", "Value"]);

        let fs = &conn.forward_secrecy;
        t.add_row(vec![
            "Forward Secrecy".to_string(),
            if fs.all_forward_secret {
                "✅ All negotiated suites".to_string()
            } else {
                "⚠️  Non-ephemeral suite negotiated".to_string()
            },
        ]);
        for p in &fs.protocols {
            t.add_row(vec![
                format!("  {}", p.version),
                format!(
                    "{} — {}",
                    if p.forward_secret { "FS" } else { "no FS" },
                    p.cipher.as_deref().unwrap_or("—"),
                ),
            ]);
        }

        let staple = &conn.ocsp_stapling;
        t.add_row(vec![
            "OCSP Stapling".to_string(),
            if staple.stapled {
                format!("✅ Yes ({} bytes)", staple.response_len)
            } else {
                "❌ No".to_string()
            },
        ]);

        let sr = &conn.session_resumption;
        t.add_row(vec![
            "Session Resumption".to_string(),
            if sr.supported {
                let mut parts = Vec::new();
                if sr.tls13_ticket {
                    parts.push("TLS 1.3 ticket");
                }
                if sr.tls12_session {
                    parts.push("TLS 1.2 session");
                }
                format!("✅ {}", parts.join(", "))
            } else {
                "❌ Not offered".to_string()
            },
        ]);

        t.add_row(vec!["SNI Behaviour".to_string(), conn.sni.outcome.to_string()]);
        if let (Some(a), Some(b)) = (&conn.sni.with_sni_subject, &conn.sni.without_sni_subject) {
            if a != b {
                t.add_row(vec!["  with SNI".to_string(), a.clone()]);
                t.add_row(vec!["  without SNI".to_string(), b.clone()]);
            }
        }

        match &conn.hsts {
            Some(h) if h.present => {
                let mut v = format!(
                    "✅ max-age={}",
                    h.max_age.map(|m| m.to_string()).unwrap_or_else(|| "?".to_string())
                );
                if h.include_subdomains {
                    v.push_str("; includeSubDomains");
                }
                if h.preload {
                    v.push_str("; preload");
                }
                t.add_row(vec!["HSTS".to_string(), v]);
            }
            Some(_) => {
                t.add_row(vec!["HSTS".to_string(), "❌ Not present".to_string()]);
            }
            None => {
                t.add_row(vec!["HSTS".to_string(), "— (probe failed)".to_string()]);
            }
        }

        println!("{t}\n");
    }

    // Vulnerabilities
    if !result.vulnerabilities.is_empty() {
        println!("⚠️  Vulnerability Checks");
        let mut t = Table::new();
        t.load_preset(UTF8_FULL);
        t.set_header(vec!["Vulnerability", "Vulnerable", "Severity", "Notes"]);
        for v in &result.vulnerabilities {
            t.add_row(vec![
                v.name.as_str(),
                if v.vulnerable { "🔴 YES" } else { "🟢 No" },
                v.severity.as_str(),
                v.description.as_str(),
            ]);
        }
        println!("{t}\n");
    }
}
