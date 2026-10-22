//! Certificates in trust stores. A hunt for `cert:FINGERPRINT` or `cert:subject:TEXT` reads the trust stores the index
//! holds (an image's layers, a host's system and certifi bundles, a repo's committed certificate files) and says, for each match,
//! the file, the certificate's subject, and whether it is a root or an intermediate. What could not be read becomes a gap row.
use super::hunt::{CertHit, FKind, Finding, NotChecked, Query};
use super::index::Index;
use super::iocs::{Ioc, IocKind};
use crate::view::{CertRec, ImageBuild, TrustFile};
use std::collections::BTreeMap;

/// Does this certificate answer the indicator: the same fingerprint, or the text inside its subject or issuer (any case).
pub fn cert_matches(ioc: &Ioc, c: &CertRec) -> bool {
    if ioc.kind != IocKind::Cert {
        return false;
    }
    if !ioc.sha.is_empty() {
        return c.fp == ioc.sha;
    }
    let n = ioc.name.to_lowercase();
    !n.is_empty() && (c.subject.to_lowercase().contains(&n) || c.issuer.to_lowercase().contains(&n))
}

fn hit(c: &CertRec, file: &str, store: &str, deleted: bool) -> CertHit {
    CertHit { fp: c.fp.clone(), subject: c.subject.clone(), issuer: c.issuer.clone(), not_after: c.not_after.clone(), root: c.root, file: file.to_string(), store: store.to_string(), deleted }
}

fn images_in_scope<'a>(ix: &'a Index, q: &Query, names: &[String]) -> Vec<(&'a ImageBuild, String)> {
    let mut out = vec![];
    if !q.has("images") {
        return out;
    }
    let by_repo = q.repo.as_ref().is_some_and(|r| !r.is_empty());
    for b in ix.images() {
        if !super::hunt::in_window_pt(q, &b.built) {
            continue;
        }
        let reg = ix.registry_of(&b.repository);
        if !by_repo {
            match &reg {
                Some(r) if names.contains(r) => {}
                _ => continue,
            }
        }
        out.push((b, reg.unwrap_or_default()));
    }
    out
}

fn removed_later(b: &ImageBuild, li: usize, path: &str, fp: &str) -> Option<u32> {
    b.layers.iter().skip(li + 1).find_map(|l| {
        let whiteout = l.whiteouts.iter().any(|w| w == path || path.starts_with(&format!("{}/", w.trim_end_matches('/'))));
        // the same file written again without the certificate
        let replaced = l.trust.iter().any(|t| t.path == path && t.gaps.is_empty() && !t.certs.iter().any(|x| x.fp == fp));
        if whiteout || replaced {
            Some(l.n)
        } else {
            None
        }
    })
}

/// The matches in image layers: one row per image, file and certificate. A copy that a later layer removed or rewrote is a deleted-layer row.
fn image_certs(ix: &Index, q: &Query, ioc: &Ioc, names: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    for (b, _) in images_in_scope(ix, q, names) {
        // the last layer that holds the certificate at each path is the one that decides whether it is still in the final image
        let mut last: BTreeMap<(String, String), (usize, &CertRec)> = BTreeMap::new();
        for (li, l) in b.layers.iter().enumerate() {
            for tf in &l.trust {
                for c in tf.certs.iter().filter(|c| cert_matches(ioc, c)) {
                    last.insert((tf.path.clone(), c.fp.clone()), (li, c));
                }
            }
        }
        for ((path, fp), (li, c)) in last {
            let layer = &b.layers[li];
            let gone = removed_later(b, li, &path, &fp);
            let src = b.source.clone().unwrap_or_default();
            let mut f = Finding::new(FKind::Image, ioc, &b.repository);
            f.image = b.repository.clone();
            f.tags = b.tags.clone();
            f.digest = b.digest.clone();
            f.built = b.built.clone();
            f.from_repo = src.repo;
            f.commit = src.commit;
            f.where_in = if gone.is_some() { "in a deleted layer (still in the image's blobs)".to_string() } else { "final image".to_string() };
            f.layer = layer.n;
            f.run_id = src.run;
            f.layer_cmd = layer.created_by.clone();
            f.layer_blob = layer.blob.clone();
            f.deleted_in = gone;
            f.path = path.clone();
            f.first_seen = Some(b.built.clone());
            f.cert = Some(hit(c, &path, crate::parse::x509::store_kind(&path), gone.is_some()));
            out.push(f);
        }
    }
    out
}

fn host_certs(ix: &Index, q: &Query, ioc: &Ioc, names: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    if !q.has("hosts") {
        return out;
    }
    for h in names.iter().filter(|n| ix.kind_of(n) == "host") {
        let Some(def) = ix.host_def(h) else { continue };
        let at = ix.it(h);
        if !super::hunt::in_window_pt(q, &at) {
            continue;
        }
        for tf in &def.trust.files {
            for c in tf.certs.iter().filter(|c| cert_matches(ioc, c)) {
                let mut f = Finding::new(FKind::Host, ioc, h);
                f.loc = tf.path.clone();
                f.item_kind = "trust store".into();
                f.state = "present".into();
                f.first_seen = Some(at.clone());
                f.cert = Some(hit(c, &tf.path, crate::parse::x509::store_kind(&tf.path), false));
                out.push(f);
            }
        }
    }
    out
}

fn repo_certs(ix: &Index, q: &Query, ioc: &Ioc, repos: &[String]) -> Vec<Finding> {
    let mut out = vec![];
    if !q.has("repos") {
        return out;
    }
    for r in repos {
        let at = ix.it(r);
        if !super::hunt::in_window_pt(q, &at) {
            continue;
        }
        for tf in &ix.repo(r).trust.files {
            for c in tf.certs.iter().filter(|c| cert_matches(ioc, c)) {
                let mut f = Finding::new(FKind::Repo, ioc, r);
                f.state = "present".into();
                f.file = tf.path.clone();
                f.version = "-".into();
                f.depth = "-".into();
                f.name = c.subject.clone();
                f.p = Some(format!("cert:{}", c.fp));
                f.first_seen = Some(at.clone());
                f.cert = Some(hit(c, &tf.path, "repo file", false));
                out.push(f);
            }
        }
    }
    out
}

/// Every place the index holds a certificate that answers `ioc`.
pub fn cert_findings(ix: &Index, q: &Query, ioc: &Ioc, repos: &[String], names: &[String]) -> Vec<Finding> {
    let mut out = image_certs(ix, q, ioc, names);
    out.extend(host_certs(ix, q, ioc, names));
    out.extend(repo_certs(ix, q, ioc, repos));
    out
}

fn short(d: &str) -> String {
    d.chars().take(19).collect()
}

fn join_reasons(rs: &[String]) -> String {
    let mut s = rs.iter().take(3).cloned().collect::<Vec<_>>().join("; ");
    if rs.len() > 3 {
        s += &format!("; and {} more", rs.len() - 3);
    }
    s
}

fn file_gaps(tf: &TrustFile) -> Vec<String> {
    tf.gaps.iter().map(|g| format!("{}: {g}", tf.path)).collect()
}

/// What a certificate hunt could not read, one row per source: images built before certificates were read, unreadable stores,
/// caps that were reached, and the store kinds br does not read on a host's OS. A hunt with a gap is never "clear".
pub fn gap_rows(ix: &Index, q: &Query, names: &[String]) -> Vec<NotChecked> {
    if !q.iocs.iter().any(|i| i.kind == IocKind::Cert) {
        return vec![];
    }
    let mut by: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
    for (b, reg) in images_in_scope(ix, q, names) {
        let label = format!("{}@{}", b.repository, short(&b.digest));
        if !b.trust_read {
            by.entry(("registry".into(), reg.clone())).or_default().push(format!("{label} was indexed before br read certificates; scan the registry again"));
        }
        for l in &b.layers {
            for tf in &l.trust {
                for g in file_gaps(tf) {
                    by.entry(("registry".into(), reg.clone())).or_default().push(format!("{label}: {g}"));
                }
            }
        }
    }
    if q.has("hosts") {
        for h in names.iter().filter(|n| ix.kind_of(n) == "host") {
            let Some(def) = ix.host_def(h) else { continue };
            let e = by.entry(("host".into(), h.clone())).or_default();
            if !def.trust.read {
                e.push("scanned before br read certificates; scan it again".into());
                continue;
            }
            for tf in &def.trust.files {
                e.extend(file_gaps(tf));
            }
            e.extend(def.trust.notes.iter().cloned());
            if q.checkout {
                continue;
            }
            let os = def.os.clone().unwrap_or_default().to_lowercase();
            if os.contains("mac") || os.contains("darwin") {
                e.push("macOS keychains are not read, so a certificate only a keychain holds would not show".into());
            } else if os.contains("win") {
                e.push("the Windows certificate store is not read, so a certificate only that store holds would not show".into());
            } else if def.trust.files.is_empty() {
                e.push("no trust store was found under the directories scanned (br looks in /etc/ssl/certs, /etc/pki and the other system trust directories)".into());
            }
        }
    }
    if q.has("repos") {
        for r in names.iter().filter(|n| ix.kind_of(n) == "repo") {
            let t = &ix.repo(r).trust;
            let e = by.entry(("repo".into(), r.clone())).or_default();
            if !t.read {
                e.push("its certificate files at HEAD were not read; scan it again".into());
                continue;
            }
            for tf in &t.files {
                e.extend(file_gaps(tf));
            }
            e.extend(t.notes.iter().cloned());
        }
    }
    let mut rows = vec![];
    for ((kind, name), rs) in by {
        if rs.is_empty() {
            continue;
        }
        let command = match kind.as_str() {
            "registry" => format!("br scan --registry {name}   (then open any unreadable file by hand: keytool -list -keystore FILE)"),
            "host" => super::hunt::close_command("host", &name, None),
            _ => format!("br scan --repo {name}"),
        };
        rows.push(NotChecked {
            name: name.clone(),
            kind,
            state: "trust store".into(),
            why: format!("trust stores not fully read: {}", join_reasons(&rs)),
            indexed_at: ix.i(&name),
            command,
            people: vec![],
        });
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert(fp: &str, subject: &str, issuer: &str) -> CertRec {
        CertRec { fp: fp.into(), subject: subject.into(), issuer: issuer.into(), not_after: None, root: subject == issuer }
    }

    fn ioc(text: &str) -> Ioc {
        super::super::iocs::parse_ioc(text, None).unwrap()
    }

    #[test]
    fn a_fingerprint_matches_in_any_case_and_a_subject_matches_a_piece_of_the_subject_or_issuer() {
        let fp = "ab".repeat(32);
        let c = cert(&fp, "CN=Example Leaf, O=Org", "CN=Example Root CA, O=Org");
        assert!(cert_matches(&ioc(&format!("cert:{}", fp.to_uppercase())), &c));
        assert!(cert_matches(&ioc("cert:subject:example root"), &c));
        assert!(cert_matches(&ioc("cert:subject:LEAF"), &c));
        assert!(!cert_matches(&ioc("cert:subject:somebody else"), &c));
        assert!(!cert_matches(&ioc(&format!("cert:{}", "cd".repeat(32))), &c));
    }
}
