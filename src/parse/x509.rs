//! A small DER / X.509 reader for trust stores: subject, issuer, notAfter and the SHA-256 fingerprint of a certificate.
//! Reads PEM bundles (also with text around the blocks), single DER certificates and plain Java keystores (JKS).
//! It does not check signatures or chains. Private keys are never kept: only certificate blocks are decoded.
use crate::view::CertRec;
use base64::Engine;
use sha2::{Digest, Sha256};

/// What reading one file found.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Read {
    pub certs: Vec<CertRec>,
    /// Plain-words lines about what could not be read.
    pub gaps: Vec<String>,
    /// The file held certificates or something that could not be read as a store (a gap): worth recording.
    pub store: bool,
}

/// Largest trust store file br reads, and the most such files read at one place.
pub const MAX_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_FILES: usize = 400;

/// Whether a path names a trust store: Some(known) when it does, where `known` means the name alone says it is a CA bundle
/// (so bytes that cannot be read are a gap). `wide` also takes any `.pem`, `.crt` or `.cer` file (images and checkouts);
/// a host takes only the system trust dirs, certifi bundles and the bundle names, so a home directory is not combed for every key file.
pub fn store_path(path: &str, wide: bool) -> Option<bool> {
    let p = path.trim_start_matches('/').to_ascii_lowercase();
    let base = p.rsplit('/').next().unwrap_or("");
    let ext = base.rsplit_once('.').map(|x| x.1).unwrap_or("");
    let cert_ext = matches!(ext, "pem" | "crt" | "cer");
    let bundle_name = base.starts_with("ca-bundle") || base.starts_with("cacert") || base == "ca-certificates.crt" || base == "tls-ca-bundle.pem" || base == "cacerts";
    let dirs = ["etc/ssl/certs/", "etc/pki/", "usr/local/share/ca-certificates/", "usr/share/ca-certificates/", "etc/ca-certificates/", "usr/lib/ssl/certs/"];
    let in_dir = dirs.iter().any(|d| p.starts_with(d) || p.contains(&format!("/{d}")));
    if bundle_name {
        return Some(true);
    }
    if in_dir && (cert_ext || wide) {
        return Some(false);
    }
    if cert_ext && (wide || p.contains("/certifi/")) {
        return Some(false);
    }
    None
}

/// What kind of store a path is, for the fix text: `certifi` (Python's bundle), `java` (a keystore), `system` (the OS trust dirs and
/// bundle names) or `file` (any other certificate file).
pub fn store_kind(path: &str) -> &'static str {
    let p = path.trim_start_matches('/').to_ascii_lowercase();
    let base = p.rsplit('/').next().unwrap_or("");
    if p.contains("/certifi/") || p.starts_with("certifi/") {
        "certifi"
    } else if base == "cacerts" || base.ends_with(".jks") || base.ends_with(".p12") || base.ends_with(".pfx") {
        "java"
    } else if ["etc/ssl/", "etc/pki/", "usr/local/share/ca-certificates/", "usr/share/ca-certificates/", "etc/ca-certificates", "usr/lib/ssl/"]
        .iter()
        .any(|d| p.starts_with(d) || p.contains(&format!("/{d}")))
    {
        "system"
    } else {
        "file"
    }
}

/// A fingerprint as people write it: with or without colons or spaces, any case. None when it is not 64 hex digits.
pub fn normalize_fp(s: &str) -> Option<String> {
    let t: String = s.chars().filter(|c| !matches!(c, ':' | ' ' | '-' | '\t')).collect::<String>().to_lowercase();
    if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(t)
    } else {
        None
    }
}

/// A whole string that is a fingerprint in colon-hex (`AB:CD:...`, 32 pairs), as openssl prints it.
pub fn colon_fingerprint(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    if parts.len() == 32 && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit())) {
        normalize_fp(s.trim())
    } else {
        None
    }
}

struct Tlv<'a> {
    tag: u8,
    /// header plus content
    whole: &'a [u8],
    content: &'a [u8],
}

fn tlv(buf: &[u8]) -> Result<(Tlv<'_>, &[u8]), String> {
    if buf.len() < 2 {
        return Err("truncated".into());
    }
    let tag = buf[0];
    if tag & 0x1f == 0x1f {
        return Err("long tags are not used in certificates".into());
    }
    let (len, hdr) = if buf[1] < 0x80 {
        (buf[1] as usize, 2)
    } else {
        let n = (buf[1] & 0x7f) as usize;
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return Err("bad length".into());
        }
        let mut l = 0usize;
        for b in &buf[2..2 + n] {
            l = (l << 8) | *b as usize;
        }
        (l, 2 + n)
    };
    let end = hdr.checked_add(len).ok_or("bad length")?;
    if buf.len() < end {
        return Err("truncated".into());
    }
    Ok((Tlv { tag, whole: &buf[..end], content: &buf[hdr..end] }, &buf[end..]))
}

fn oid_short(content: &[u8]) -> Option<&'static str> {
    // per-format table of attribute types a distinguished name carries (RFC 4519 / 5280 short names)
    Some(match content {
        [0x55, 0x04, 0x03] => "CN",
        [0x55, 0x04, 0x04] => "SN",
        [0x55, 0x04, 0x05] => "serialNumber",
        [0x55, 0x04, 0x06] => "C",
        [0x55, 0x04, 0x07] => "L",
        [0x55, 0x04, 0x08] => "ST",
        [0x55, 0x04, 0x09] => "street",
        [0x55, 0x04, 0x0a] => "O",
        [0x55, 0x04, 0x0b] => "OU",
        [0x55, 0x04, 0x0c] => "title",
        [0x55, 0x04, 0x2a] => "GN",
        [0x55, 0x04, 0x61] => "organizationIdentifier",
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "emailAddress",
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC",
        _ => return None,
    })
}

fn dotted(content: &[u8]) -> String {
    let mut parts: Vec<String> = vec![];
    let mut v: u64 = 0;
    for b in content {
        v = (v << 7) | (*b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if parts.is_empty() {
                let first = (v / 40).min(2);
                parts.push(first.to_string());
                parts.push((v - 40 * first).to_string());
            } else {
                parts.push(v.to_string());
            }
            v = 0;
        }
    }
    parts.join(".")
}

fn text_value(t: &Tlv) -> String {
    match t.tag {
        0x1e => {
            // BMPString: UTF-16BE
            let u: Vec<u16> = t.content.chunks(2).filter(|c| c.len() == 2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&u)
        }
        0x1c => t.content.chunks(4).filter(|c| c.len() == 4).filter_map(|c| char::from_u32(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))).collect(),
        0x0c | 0x13 | 0x16 | 0x14 | 0x12 | 0x1a => String::from_utf8_lossy(t.content).into_owned(),
        _ => format!("#{}", hex::encode(t.content)),
    }
}

/// A distinguished name as `CN=..., O=..., C=...` (the most specific part first, as RFC 4514 writes it).
fn name(content: &[u8]) -> Result<String, String> {
    let mut rdns: Vec<String> = vec![];
    let mut rest = content;
    while !rest.is_empty() {
        let (set, r) = tlv(rest)?;
        rest = r;
        if set.tag != 0x31 {
            return Err("name is not a set".into());
        }
        let mut atvs: Vec<String> = vec![];
        let mut inner = set.content;
        while !inner.is_empty() {
            let (seq, r) = tlv(inner)?;
            inner = r;
            let (oid, r2) = tlv(seq.content)?;
            let (val, _) = tlv(r2)?;
            if oid.tag != 0x06 {
                return Err("name attribute without a type".into());
            }
            let key = oid_short(oid.content).map(str::to_string).unwrap_or_else(|| dotted(oid.content));
            let v = text_value(&val).replace(',', "\\,");
            atvs.push(format!("{key}={v}"));
        }
        rdns.push(atvs.join("+"));
    }
    rdns.reverse();
    Ok(rdns.join(", "))
}

fn two(b: &[u8]) -> Option<u32> {
    if b.len() == 2 && b.iter().all(u8::is_ascii_digit) {
        Some(((b[0] - b'0') * 10 + (b[1] - b'0')) as u32)
    } else {
        None
    }
}

/// UTCTime or GeneralizedTime to `YYYY-MM-DDTHH:MM:SSZ`.
fn time(t: &Tlv) -> Option<String> {
    let c = t.content;
    let (year, rest) = match t.tag {
        0x17 if c.len() >= 2 => {
            let yy = two(&c[..2])?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, &c[2..])
        }
        0x18 if c.len() >= 4 => (two(&c[..2])? * 100 + two(&c[2..4])?, &c[4..]),
        _ => return None,
    };
    let mo = two(rest.get(0..2)?)?;
    let d = two(rest.get(2..4)?)?;
    let h = two(rest.get(4..6)?)?;
    let mi = two(rest.get(6..8)?)?;
    let s = rest.get(8..10).and_then(two).unwrap_or(0);
    Some(format!("{year:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}Z"))
}

/// Read one DER certificate.
pub fn parse_der(der: &[u8]) -> Result<CertRec, String> {
    let (cert, _) = tlv(der)?;
    if cert.tag != 0x30 {
        return Err("not a certificate (no outer sequence)".into());
    }
    let (tbs, _) = tlv(cert.content)?;
    if tbs.tag != 0x30 {
        return Err("not a certificate (no TBS sequence)".into());
    }
    let mut rest = tbs.content;
    let (mut f, r) = tlv(rest)?;
    rest = r;
    if f.tag == 0xa0 {
        // explicit version
        let (n, r) = tlv(rest)?;
        f = n;
        rest = r;
    }
    if f.tag != 0x02 {
        return Err("no serial number".into());
    }
    let (sigalg, r) = tlv(rest)?;
    if sigalg.tag != 0x30 {
        return Err("no signature algorithm".into());
    }
    let (issuer, r) = tlv(r)?;
    let (validity, r) = tlv(r)?;
    let (subject, _) = tlv(r)?;
    if issuer.tag != 0x30 || validity.tag != 0x30 || subject.tag != 0x30 {
        return Err("issuer, validity or subject missing".into());
    }
    let (nb, r) = tlv(validity.content)?;
    let (na, _) = tlv(r)?;
    let _ = nb;
    Ok(CertRec { fp: hex::encode(Sha256::digest(cert.whole)), subject: name(subject.content)?, issuer: name(issuer.content)?, not_after: time(&na), root: issuer.content == subject.content })
}

/// The base64 bodies of the certificate blocks in a PEM text, and how many blocks could not be decoded.
fn pem_blocks(text: &str) -> Vec<Result<Vec<u8>, String>> {
    let mut out = vec![];
    let mut cur: Option<String> = None;
    let mut keep = false;
    for line in text.lines() {
        let l = line.trim();
        if let Some(lab) = l.strip_prefix("-----BEGIN ").and_then(|x| x.strip_suffix("-----")) {
            // CERTIFICATE, TRUSTED CERTIFICATE, X509 CERTIFICATE; not a request, a key or a CRL
            keep = lab.ends_with("CERTIFICATE") && !lab.contains("REQUEST");
            cur = Some(String::new());
        } else if l.starts_with("-----END ") {
            if let (Some(b), true) = (cur.take(), keep) {
                let clean: String = b.chars().filter(|c| !c.is_whitespace()).collect();
                out.push(base64::engine::general_purpose::STANDARD.decode(clean.as_bytes()).map_err(|_| "base64 did not decode".to_string()));
            }
            keep = false;
        } else if let Some(b) = cur.as_mut() {
            if keep && !l.contains(':') {
                b.push_str(l);
            }
        }
    }
    // a block that never ended
    if let (Some(b), true) = (cur, keep) {
        if !b.trim().is_empty() {
            out.push(Err("the block is cut off".to_string()));
        }
    }
    out
}

fn be32(b: &[u8], at: &mut usize) -> Option<u32> {
    let s = b.get(*at..*at + 4)?;
    *at += 4;
    Some(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
}

fn jks_utf(b: &[u8], at: &mut usize) -> Option<()> {
    let s = b.get(*at..*at + 2)?;
    let n = u16::from_be_bytes([s[0], s[1]]) as usize;
    b.get(*at + 2..*at + 2 + n)?;
    *at += 2 + n;
    Some(())
}

/// Plain Java keystore: trusted-certificate entries and the certificate chains of key entries. Key material is skipped.
fn read_jks(b: &[u8], r: &mut Read) {
    let mut at = 4;
    let ver = be32(b, &mut at);
    let n = be32(b, &mut at);
    let (Some(ver), Some(n)) = (ver, n) else {
        r.gaps.push("the Java keystore header is cut off".into());
        return;
    };
    if ver != 1 && ver != 2 {
        r.gaps.push(format!("Java keystore version {ver} is not one br reads"));
        return;
    }
    let mut bad = 0;
    let cut = |r: &mut Read, got: usize| r.gaps.push(format!("the Java keystore is cut off or damaged after {got} entries"));
    for i in 0..n {
        let Some(tag) = be32(b, &mut at) else { return cut(r, i as usize) };
        if jks_utf(b, &mut at).is_none() || b.get(at..at + 8).is_none() {
            return cut(r, i as usize);
        }
        at += 8;
        let mut certs: Vec<&[u8]> = vec![];
        match tag {
            1 => {
                let Some(klen) = be32(b, &mut at) else { return cut(r, i as usize) };
                if b.get(at..at + klen as usize).is_none() {
                    return cut(r, i as usize);
                }
                at += klen as usize;
                let Some(cn) = be32(b, &mut at) else { return cut(r, i as usize) };
                for _ in 0..cn {
                    if ver == 2 && jks_utf(b, &mut at).is_none() {
                        return cut(r, i as usize);
                    }
                    let Some(l) = be32(b, &mut at) else { return cut(r, i as usize) };
                    let Some(c) = b.get(at..at + l as usize) else { return cut(r, i as usize) };
                    at += l as usize;
                    certs.push(c);
                }
            }
            2 => {
                if ver == 2 && jks_utf(b, &mut at).is_none() {
                    return cut(r, i as usize);
                }
                let Some(l) = be32(b, &mut at) else { return cut(r, i as usize) };
                let Some(c) = b.get(at..at + l as usize) else { return cut(r, i as usize) };
                at += l as usize;
                certs.push(c);
            }
            _ => return cut(r, i as usize),
        }
        for c in certs {
            match parse_der(c) {
                Ok(c) => r.certs.push(c),
                Err(_) => bad += 1,
            }
        }
    }
    if bad > 0 {
        r.gaps.push(format!("{bad} certificate{} in the Java keystore could not be read", if bad == 1 { "" } else { "s" }));
    }
}

/// Read the bytes of a file that is (or may be) a trust store. `known` says the path alone marks it a trust store
/// (a system bundle, a Java cacerts): then bytes that are not readable are a gap, never silence.
pub fn read_store(bytes: &[u8], known: bool) -> Read {
    let mut r = Read::default();
    if bytes.starts_with(&[0xfe, 0xed, 0xfe, 0xed]) {
        r.store = true;
        read_jks(bytes, &mut r);
        return r;
    }
    if bytes.starts_with(&[0xce, 0xce, 0xce, 0xce]) {
        r.store = true;
        r.gaps.push("Java JCEKS keystore: not read (br reads plain JKS and PEM bundles only)".into());
        return r;
    }
    let text_like = bytes.windows(11).any(|w| w == b"-----BEGIN ");
    if text_like {
        let text = String::from_utf8_lossy(bytes);
        let blocks = pem_blocks(&text);
        let mut bad = 0;
        for b in blocks {
            match b.and_then(|d| parse_der(&d)) {
                Ok(c) => r.certs.push(c),
                Err(_) => bad += 1,
            }
        }
        if bad > 0 {
            r.gaps.push(format!("{bad} certificate{} in this file could not be read", if bad == 1 { "" } else { "s" }));
        }
        r.store = !r.certs.is_empty() || bad > 0;
        if !r.store && known && !bytes.windows(15).any(|w| w == b"PRIVATE KEY----") {
            r.store = true;
            r.gaps.push("no certificate could be read from this trust store file".into());
        }
        return r;
    }
    if bytes.first() == Some(&0x30) {
        match parse_der(bytes) {
            Ok(c) => {
                r.certs.push(c);
                r.store = true;
            }
            Err(e) => {
                // PKCS#12 (keystores such as Java's newer cacerts) is the same outer shape; its content is encrypted or in a format not read
                if known || bytes.windows(9).any(|w| w == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a] || w[..8] == [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c]) {
                    r.store = true;
                    r.gaps.push(format!("PKCS#12 or binary keystore: not read ({e}); give br a PEM export or an unencrypted JKS"));
                }
            }
        }
        return r;
    }
    if known && !bytes.is_empty() {
        r.store = true;
        r.gaps.push("not a certificate format br reads (PEM, DER or plain JKS)".into());
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    const PEM: &str = "-----BEGIN CERTIFICATE-----
MIIByTCCAXCgAwIBAgIBTTAKBggqhkjOPQQDAjBEMQswCQYDVQQGEwJaWjEZMBcG
A1UECgwQRXhhbXBsZSBUZXN0IE9yZzEaMBgGA1UEAwwRRXhhbXBsZSBUZXN0IFJv
b3QwHhcNMjYxMDIyMDU0NzQwWhcNMzYxMDE5MDU0NzQwWjBEMQswCQYDVQQGEwJa
WjEZMBcGA1UECgwQRXhhbXBsZSBUZXN0IE9yZzEaMBgGA1UEAwwRRXhhbXBsZSBU
ZXN0IFJvb3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAT2ez0O7/ahPTqgIEq6
cVmzN0SXkVZR5B4exHgbCqd95yVKIpEWPNaJ/0RLtmonit1M4ynrseD/2gh+9kjx
GpP5o1MwUTAdBgNVHQ4EFgQUSWvD74hgY0Clf5YvaXI+wBqt0acwHwYDVR0jBBgw
FoAUSWvD74hgY0Clf5YvaXI+wBqt0acwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjO
PQQDAgNHADBEAiA/OqTh5Ute69YepwrAWdhQVrhqmghg17tZEW6ps+vIrwIgNZPM
dC/i1I4vcFNNVJ9b0Se7AfNKBq63lyELsuxUm68=
-----END CERTIFICATE-----
";
    const FP: &str = "4e87897a491921221041e17b0cbbf6b437dd87349e5524abd64b954af8c4bcd4d";

    fn der() -> Vec<u8> {
        let body: String = PEM.lines().filter(|l| !l.starts_with("-----")).collect();
        base64::engine::general_purpose::STANDARD.decode(body).unwrap()
    }

    #[test]
    fn reads_a_pem_cert() {
        let r = read_store(PEM.as_bytes(), false);
        assert!(r.gaps.is_empty(), "{:?}", r.gaps);
        assert_eq!(r.certs.len(), 1);
        let c = &r.certs[0];
        assert_eq!(c.fp.len(), 64);
        assert_eq!(c.subject, "CN=Example Test Root, O=Example Test Org, C=ZZ");
        assert_eq!(c.issuer, c.subject);
        assert!(c.root);
        assert_eq!(c.not_after.as_deref(), Some("2036-10-19T05:47:40Z"));
        let _ = FP;
    }

    #[test]
    fn der_and_pem_agree() {
        let a = parse_der(&der()).unwrap();
        let b = &read_store(PEM.as_bytes(), false).certs[0];
        assert_eq!(&a, b);
        assert_eq!(read_store(&der(), false).certs.len(), 1);
    }

    #[test]
    fn a_bad_cert_in_a_bundle_is_a_gap_not_a_clear() {
        let bundle = format!("{PEM}-----BEGIN CERTIFICATE-----\nAAAAAAAA\n-----END CERTIFICATE-----\n{PEM}");
        let r = read_store(bundle.as_bytes(), false);
        assert_eq!(r.certs.len(), 2);
        assert_eq!(r.gaps.len(), 1);
        assert!(r.store);
    }

    #[test]
    fn a_private_key_is_not_kept_or_counted() {
        let r = read_store(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", true);
        assert!(r.certs.is_empty() && r.gaps.is_empty() && !r.store);
    }

    #[test]
    fn unreadable_known_store_is_a_gap() {
        let r = read_store(&[0x30, 0x82, 0x01, 0x00, 1, 2, 3], true);
        assert!(r.store && !r.gaps.is_empty());
        assert!(read_store(b"\x00\x01\x02", false).gaps.is_empty());
        assert!(!read_store(b"\x00\x01\x02", true).gaps.is_empty());
    }

    #[test]
    fn plain_jks_is_read() {
        let d = der();
        let mut j = vec![0xfe, 0xed, 0xfe, 0xed, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 3];
        j.extend_from_slice(b"abc");
        j.extend_from_slice(&[0; 8]);
        j.extend_from_slice(&[0, 5]);
        j.extend_from_slice(b"X.509");
        j.extend_from_slice(&(d.len() as u32).to_be_bytes());
        j.extend_from_slice(&d);
        j.extend_from_slice(&[0; 20]);
        let r = read_store(&j, true);
        assert_eq!(r.certs.len(), 1, "{:?}", r.gaps);
        assert!(r.gaps.is_empty());
        j.truncate(40);
        assert!(!read_store(&j, true).gaps.is_empty());
    }

    #[test]
    fn fingerprints_normalise() {
        let a = "4E:87:89:7A:49:19:21:22:04:1E:17:B0:CB:BF:6B:43:7D:D8:73:49:E5:52:4A:BD:64:B9:54:AF:8C:4B:CD:4D";
        let n = normalize_fp(a).unwrap();
        assert_eq!(n.len(), 64);
        assert_eq!(normalize_fp(&n.to_uppercase()), Some(n));
        assert!(normalize_fp("abc").is_none());
    }

    #[test]
    fn fingerprint_matches_openssl() {
        let r = read_store(PEM.as_bytes(), false);
        assert_eq!(r.certs[0].fp, "4e87897a49192122041e17b0cbbf6b437dd87349e5524abd64b954af8c4bcd4d");
    }
}
