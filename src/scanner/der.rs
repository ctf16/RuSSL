//! Minimal DER encoder and a non-allocating TLV reader.
//!
//! Just enough ASN.1 to build an OCSP request and walk an OCSP response. This
//! is deliberately tiny: we never sign or fully decode, we only assemble fixed
//! request shapes and navigate a response positionally.

/// `AlgorithmIdentifier` for SHA-1: `SEQUENCE { OID 1.3.14.3.2.26, NULL }`.
pub const ALGID_SHA1: [u8; 11] = [
    0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00,
];

/// Encode a DER length field (definite, short or long form).
fn encode_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut be = Vec::new();
    let mut n = len;
    while n > 0 {
        be.push((n & 0xff) as u8);
        n >>= 8;
    }
    be.reverse();
    let mut out = Vec::with_capacity(be.len() + 1);
    out.push(0x80 | be.len() as u8);
    out.extend_from_slice(&be);
    out
}

/// Encode a tag-length-value triple.
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let len = encode_len(content.len());
    let mut out = Vec::with_capacity(1 + len.len() + content.len());
    out.push(tag);
    out.extend_from_slice(&len);
    out.extend_from_slice(content);
    out
}

/// `SEQUENCE { content }`.
pub fn sequence(content: &[u8]) -> Vec<u8> {
    tlv(0x30, content)
}

/// `OCTET STRING { content }`.
pub fn octet_string(content: &[u8]) -> Vec<u8> {
    tlv(0x04, content)
}

/// `INTEGER` from raw value octets, inserting a leading `0x00` if the high bit
/// is set so the value stays positive. An empty input encodes as `0`.
pub fn integer(value: &[u8]) -> Vec<u8> {
    if value.is_empty() {
        return tlv(0x02, &[0]);
    }
    if value[0] & 0x80 != 0 {
        let mut v = Vec::with_capacity(value.len() + 1);
        v.push(0);
        v.extend_from_slice(value);
        tlv(0x02, &v)
    } else {
        tlv(0x02, value)
    }
}

/// A parsed tag-length-value view borrowing the source buffer.
pub struct Tlv<'a> {
    pub tag: u8,
    pub content: &'a [u8],
    /// Total encoded size (header + content), used to advance to the next TLV.
    pub total_len: usize,
}

/// Read a single DER TLV from the front of `data`. Returns `None` on any
/// truncation or unsupported (indefinite / >4-octet) length.
pub fn read_tlv(data: &[u8]) -> Option<Tlv<'_>> {
    if data.len() < 2 {
        return None;
    }
    let tag = data[0];
    let first = data[1];
    let (content_len, header_len) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return None;
        }
        let mut len = 0usize;
        for &b in &data[2..2 + n] {
            len = (len << 8) | b as usize;
        }
        (len, 2 + n)
    };
    let end = header_len.checked_add(content_len)?;
    if data.len() < end {
        return None;
    }
    Some(Tlv {
        tag,
        content: &data[header_len..end],
        total_len: end,
    })
}

/// Split a constructed value's content into its child TLVs in order.
pub fn children(content: &[u8]) -> Vec<Tlv<'_>> {
    let mut out = Vec::new();
    let mut rest = content;
    while let Some(t) = read_tlv(rest) {
        let advance = t.total_len;
        out.push(t);
        if advance == 0 || advance > rest.len() {
            break;
        }
        rest = &rest[advance..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_encoding() {
        assert_eq!(encode_len(0), vec![0x00]);
        assert_eq!(encode_len(127), vec![0x7f]);
        assert_eq!(encode_len(128), vec![0x81, 0x80]);
        assert_eq!(encode_len(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn integer_sign_handling() {
        assert_eq!(integer(&[0x05]), vec![0x02, 0x01, 0x05]);
        assert_eq!(integer(&[0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer(&[]), vec![0x02, 0x01, 0x00]);
        // already has leading zero -> not doubled
        assert_eq!(integer(&[0x00, 0x80]), vec![0x02, 0x02, 0x00, 0x80]);
    }

    #[test]
    fn tlv_constructors() {
        assert_eq!(octet_string(&[1, 2]), vec![0x04, 0x02, 1, 2]);
        assert_eq!(sequence(&[]), vec![0x30, 0x00]);
    }

    #[test]
    fn read_and_walk() {
        let inner = sequence(&[octet_string(&[0xaa]), integer(&[0x01])].concat());
        let t = read_tlv(&inner).unwrap();
        assert_eq!(t.tag, 0x30);
        assert_eq!(t.total_len, inner.len());
        let kids = children(t.content);
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].tag, 0x04);
        assert_eq!(kids[0].content, &[0xaa]);
        assert_eq!(kids[1].tag, 0x02);
        assert_eq!(kids[1].content, &[0x01]);
    }

    #[test]
    fn read_long_form_length() {
        let body = vec![0x41u8; 300];
        let encoded = octet_string(&body);
        let t = read_tlv(&encoded).unwrap();
        assert_eq!(t.tag, 0x04);
        assert_eq!(t.content.len(), 300);
    }

    #[test]
    fn truncated_is_none() {
        assert!(read_tlv(&[0x30]).is_none());
        assert!(read_tlv(&[0x04, 0x05, 0x01]).is_none());
    }
}
