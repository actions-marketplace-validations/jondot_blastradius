//! Shell words for the commands br prints: quoting for POSIX sh and PowerShell, paths, hashing, and per-registry
//! delete commands. Every interpolated value goes through `shquote`/`psq`; nothing is pasted raw.

use crate::query::util::basename;

/// Python's `shlex.quote` (the `shell_words` rule): safe words stay bare, everything else is single-quoted.
pub fn shquote(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c)) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

/// A path as a shell word. A leading `~/` stays outside the quotes so the shell still expands it.
pub fn shpath(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) if !rest.is_empty() => format!("~/{}", shquote(rest)),
        _ => shquote(p),
    }
}

/// PowerShell single-quoted string (a quote is doubled). Used with -LiteralPath, so no wildcard is expanded.
pub fn psq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// `C:\Users\x`, `C:/Users/x` or a UNC path: the location itself says the host is Windows.
pub fn is_win_path(p: &str) -> bool {
    let b = p.as_bytes();
    (b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && (b[2] == b'\\' || b[2] == b'/')) || p.starts_with("\\\\")
}

/// Last component of a POSIX or Windows path.
pub fn leaf(p: &str) -> &str {
    let t = p.trim_end_matches(['/', '\\']);
    t.rsplit(['/', '\\']).next().unwrap_or(t)
}

/// A value used as part of a file name: a run of separators and odd characters becomes one `_`, and none is added at an end.
pub fn file_safe(s: &str) -> String {
    let mut t = String::new();
    let mut sep = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || "._-".contains(c) {
            if sep && !t.is_empty() {
                t.push('_');
            }
            sep = false;
            t.push(c);
        } else {
            sep = true;
        }
    }
    if t.is_empty() {
        "x".into()
    } else {
        t
    }
}

/// The hash of FILE on a POSIX box: sha256sum (GNU, Alpine, busybox) or, where it is missing, shasum (macOS, Perl).
pub fn hash_cmd(file: &str) -> String {
    let f = shquote(file);
    format!("(sha256sum {f} 2>/dev/null || shasum -a 256 {f})")
}

/// Escape the glob characters `gh release download --pattern` treats specially (the pattern is a path.Match glob).
pub fn glob_escape(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        if "*?[]\\".contains(c) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

/// Directory of a repo path: "" for the repo root.
pub fn dir_of(p: &str) -> &str {
    match p.rfind('/') {
        Some(i) => &p[..i],
        None => "",
    }
}

/// The name of a file in a repo path (kept here so callers need one import).
pub fn base(p: &str) -> &str {
    basename(p)
}

// ---- A package's own files --------------------------------------------------------------------------
/// `eco:name@version` -> (eco, name, version). A scoped name keeps its leading `@`.
pub fn split_pkg(p: &str) -> (&str, &str, &str) {
    let (eco, rest) = p.split_once(':').unwrap_or(("", p));
    match rest.rfind('@') {
        Some(i) if i > 0 => (eco, &rest[..i], &rest[i + 1..]),
        _ => (eco, rest, ""),
    }
}

/// The wheel/dist-info spelling of a PyPI name: runs of `-_.` become `_`.
pub fn dist_name(n: &str) -> String {
    n.to_lowercase().replace(['-', '.'], "_")
}

/// A `find -iname` pattern for a dist-info folder: `-`, `_` and `.` in the name all match one character.
pub fn dist_info_pattern(name: &str, ver: &str) -> String {
    let n: String = name.chars().map(|c| if matches!(c, '-' | '_' | '.') { '?' } else { c }).collect();
    format!("{n}?{ver}.dist-info")
}

/// The Python that owns a `site-packages` folder, from its path: a virtualenv or conda prefix has its own `bin/python`
/// (`Scripts\python.exe` on Windows); a user or system install (`~/.local`, `/usr`, `/usr/local`) is the `pythonX.Y` of that
/// folder; a path that says nothing falls back to `python3`.
pub fn python_for(loc: &str) -> String {
    if is_win_path(loc) {
        let l = loc.replace('/', "\\");
        return match l.to_lowercase().rfind("\\lib\\site-packages") {
            Some(i) => format!("{}\\Scripts\\python.exe", &l[..i]),
            None => "py".into(),
        };
    }
    let c: Vec<&str> = loc.trim_end_matches('/').split('/').collect();
    let n = c.len();
    if n >= 4 && matches!(c[n - 1], "site-packages" | "dist-packages") && c[n - 2].starts_with("python") && matches!(c[n - 3], "lib" | "lib64") {
        let prefix = c[..n - 3].join("/");
        let py = c[n - 2];
        return match prefix.as_str() {
            "" | "/usr" | "/usr/local" | "/opt/homebrew" => py.to_string(),
            p if p.ends_with("/.local") => py.to_string(),
            p => format!("{p}/bin/python"),
        };
    }
    "python3".into()
}

/// A path in the Go module cache: `~/go/pkg/mod/github.com/x/y@v1.2.3[/file]` -> (`~/go/pkg/mod`, `github.com/x/y`,
/// `v1.2.3`, `~/go/pkg/mod/github.com/x/y@v1.2.3`): the cache, the module path as the cache spells it, the version, and the
/// module's own folder. None when the path is not inside a module folder.
pub fn go_mod_parts(loc: &str) -> Option<(String, String, String, String)> {
    let c: Vec<&str> = loc.trim_end_matches('/').split('/').collect();
    let i = c.windows(2).position(|w| w[0] == "pkg" && w[1] == "mod")?;
    if c.get(i + 2) == Some(&"cache") {
        return None;
    }
    let j = (i + 2..c.len()).find(|&j| c[j].contains('@'))?;
    let (m, v) = c[j].split_once('@')?;
    let mut mp: Vec<&str> = c[i + 2..j].to_vec();
    mp.push(m);
    Some((c[..i + 2].join("/"), mp.join("/"), v.to_string(), c[..=j].join("/")))
}

// ---- registries ---------------------------------------------------------------------------------------------
/// Who is the owner of a registry namespace, as far as the index knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKind {
    Org,
    User,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registry {
    Ghcr { owner: String, name: String },
    DockerHub { ns: String, repo: String },
    Ecr { account: String, region: String, repo: String },
    Gar { host: String, path: String },
    Acr { registry: String, repo: String },
    Other { host: String },
}

/// Classify `host/path` the way the registry's own delete tool needs it.
pub fn classify(image: &str) -> Registry {
    let parts: Vec<&str> = image.split('/').collect();
    let host = parts[0];
    let rest = parts[1..].join("/");
    if host == "ghcr.io" && parts.len() >= 3 {
        return Registry::Ghcr { owner: parts[1].to_string(), name: parts[2..].join("/") };
    }
    if matches!(host, "docker.io" | "index.docker.io" | "registry-1.docker.io" | "registry.hub.docker.com") {
        let (ns, repo) = match rest.split_once('/') {
            Some((n, r)) => (n.to_string(), r.to_string()),
            None => ("library".to_string(), rest.clone()),
        };
        return Registry::DockerHub { ns, repo };
    }
    // ACCOUNT.dkr.ecr.REGION.amazonaws.com[.cn]
    let h: Vec<&str> = host.split('.').collect();
    if h.len() >= 6 && h[1] == "dkr" && h[2] == "ecr" && !rest.is_empty() {
        return Registry::Ecr { account: h[0].to_string(), region: h[3].to_string(), repo: rest };
    }
    if host.ends_with("-docker.pkg.dev") && parts.len() >= 4 {
        return Registry::Gar { host: host.to_string(), path: image.to_string() };
    }
    if let Some(name) = host.strip_suffix(".azurecr.io") {
        return Registry::Acr { registry: name.to_string(), repo: rest };
    }
    // a bare `name` or `ns/name` with no registry host is Docker Hub
    if !host.contains('.') && !host.contains(':') && host != "localhost" {
        let (ns, repo) = match image.split_once('/') {
            Some((n, r)) => (n.to_string(), r.to_string()),
            None => ("library".to_string(), image.to_string()),
        };
        return Registry::DockerHub { ns, repo };
    }
    Registry::Other { host: host.to_string() }
}

/// (delete command for the manifest `digest`, note or None). `digest` may be a shell expression such as `"$d"`.
/// `tags` are used only where the registry can delete tags but not digests (Docker Hub).
/// Syntax: gh api (DELETE /{orgs|users}/OWNER/packages/container/NAME/versions/ID, with --paginate on the list call:
/// https://docs.github.com/rest/packages/packages); aws ecr batch-delete-image --repository-name --image-ids
/// imageDigest=...; gcloud artifacts docker images delete IMAGE@DIGEST --delete-tags; az acr repository delete --name
/// REGISTRY --image REPO@DIGEST --yes; Docker Hub DELETE /v2/repositories/NS/REPO/tags/TAG/; crane delete IMAGE@DIGEST.
pub fn delete_cmd(image: &str, digest: &str, tags: &[String], owner: OwnerKind) -> (String, Option<String>) {
    let q = |s: &str| if s.contains('$') { format!("\"{s}\"") } else { shquote(s) };
    match classify(image) {
        Registry::Ghcr { owner: o, name } => {
            let n = name.replace('/', "%2F");
            let sel = if digest.contains('$') { format!("'.[] | select(.name==\"'\"{digest}\"'\") | .id'") } else { format!("'.[] | select(.name==\"{digest}\") | .id'") };
            let build = |seg: &str| {
                let base = shquote(&format!("/{seg}/{o}/packages/container/{n}/versions"));
                // --paginate: the versions list is 30 per page; without it a package with more versions looks empty.
                // The id is checked before DELETE so an empty lookup can never DELETE the whole /versions collection.
                format!("id=$(gh api --paginate {base} --jq {sel}) && [ -n \"$id\" ] && gh api -X DELETE {base}/\"$id\"")
            };
            match owner {
                OwnerKind::Org => (build("orgs"), None),
                OwnerKind::User => (build("users"), None),
                OwnerKind::Unknown => (
                    format!("seg=$(gh api users/{o} --jq 'if .type==\"Organization\" then \"orgs\" else \"users\" end'); {}", build("$seg")),
                    Some(format!("{o} is not known to the index as an org or a user, so the command asks GitHub (gh api users/{o})")),
                ),
            }
        }
        Registry::DockerHub { ns, repo } => {
            let t = tags.first().cloned();
            match t {
                Some(t) => (
                    format!("curl -fsS -X DELETE -H \"Authorization: Bearer $DOCKERHUB_TOKEN\" https://hub.docker.com/v2/repositories/{}/{}/tags/{}/", shquote(&ns), shquote(&repo), shquote(&t)),
                    Some("Docker Hub deletes tags, not digests; $DOCKERHUB_TOKEN is a token from POST https://hub.docker.com/v2/users/login. A digest with no tag cannot be deleted through the API: use the Docker Hub UI".into()),
                ),
                None => (
                    format!("echo {}", shquote(&format!("{image}@{digest}: Docker Hub cannot delete a digest with no tag through its API; delete it in the Docker Hub UI"))),
                    Some("Docker Hub has no delete-by-digest API".into()),
                ),
            }
        }
        Registry::Ecr { account, region, repo } => {
            (format!("aws ecr batch-delete-image --registry-id {} --region {} --repository-name {} --image-ids imageDigest={}", shquote(&account), shquote(&region), shquote(&repo), q(digest)), None)
        }
        Registry::Gar { path, .. } => (format!("gcloud artifacts docker images delete {}@{} --delete-tags", shquote(&path), q(digest)), None),
        Registry::Acr { registry, repo } => (format!("az acr repository delete --name {} --image {}@{} --yes", shquote(&registry), shquote(&repo), q(digest)), None),
        Registry::Other { .. } => (
            format!("crane delete {}@{}", shquote(image), q(digest)),
            Some("crane delete needs a registry that allows manifest DELETE (Harbor, Artifactory and GitLab often restrict it); if it is refused, delete in the registry's UI".into()),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_matches_shlex() {
        assert_eq!(shquote("a b"), "'a b'");
        assert_eq!(shquote("it's"), "'it'\"'\"'s'");
        assert_eq!(shquote("$HOME;rm"), "'$HOME;rm'");
        assert_eq!(shquote(""), "''");
        assert_eq!(shquote("acme/web"), "acme/web");
    }

    #[test]
    fn tilde_stays_expandable() {
        assert_eq!(shpath("~/Library/pnpm store"), "~/'Library/pnpm store'");
        assert_eq!(shpath("/Users/John Smith/x"), "'/Users/John Smith/x'");
    }

    #[test]
    fn powershell_quote_doubles() {
        assert_eq!(psq("C:\\Users\\O'Neil"), "'C:\\Users\\O''Neil'");
        assert!(is_win_path("C:\\Users\\dev\\AppData"));
        assert!(is_win_path("c:/x"));
        assert!(is_win_path("\\\\srv\\share"));
        assert!(!is_win_path("/home/x"));
        assert_eq!(leaf("C:\\Users\\dev\\npm-cache\\"), "npm-cache");
    }

    #[test]
    fn file_names_collapse_separators() {
        assert_eq!(file_safe("Lena Fischer (@lfischer)"), "Lena_Fischer_lfischer");
        assert_eq!(file_safe("a  //  b"), "a_b");
        assert_eq!(file_safe("???"), "x");
    }

    #[test]
    fn globs_are_escaped() {
        assert_eq!(glob_escape("app[linux]*.tar.gz"), "app\\[linux\\]\\*.tar.gz");
    }

    #[test]
    fn registries_are_classified_by_host() {
        assert!(matches!(classify("ghcr.io/acme/web"), Registry::Ghcr { .. }));
        assert!(matches!(classify("123456789012.dkr.ecr.eu-west-1.amazonaws.com/web"), Registry::Ecr { .. }));
        assert!(matches!(classify("europe-docker.pkg.dev/proj/repo/img"), Registry::Gar { .. }));
        assert!(matches!(classify("acme.azurecr.io/web"), Registry::Acr { .. }));
        assert!(matches!(classify("docker.io/acme/web"), Registry::DockerHub { .. }));
        assert!(matches!(classify("registry.example.com/web"), Registry::Other { .. }));
    }
}
