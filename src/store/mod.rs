//! The index: one SQLite file at `BR_HOME/index.db`. Observations (what the sources say) live in `obs` with
//! `first_seen`, `last_seen` and `removed_at`; br's own state (custody, imports, scans, yara hits, last scan) has its own
//! tables. `load_view` turns the present observations into a `View`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rusqlite::{params, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::view::*;

/// Bumped when the tables change shape; an index from a newer br is refused instead of misread.
pub const SCHEMA_VERSION: i64 = 1;

pub const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS sources(
  name TEXT PRIMARY KEY, kind TEXT NOT NULL, reach TEXT NOT NULL, indexed_at TEXT NOT NULL, empty INT NOT NULL DEFAULT 0,
  first_seen TEXT, removed_at TEXT);
CREATE TABLE IF NOT EXISTS obs(
  source TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL, data TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, removed_at TEXT,
  PRIMARY KEY(source, kind, key));
CREATE TABLE IF NOT EXISTS custody(id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS yara_hits(id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS imports(host TEXT PRIMARY KEY, data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS gaps(source TEXT NOT NULL, scope TEXT NOT NULL, reason TEXT NOT NULL, at TEXT NOT NULL, PRIMARY KEY(source, scope));
";

/// The pseudo-source holding org-wide observations (people, teams).
pub const ORG: &str = "_org";

pub struct Store {
    pub conn: Connection,
    pub path: PathBuf,
}

pub struct Row {
    pub kind: &'static str,
    pub key: String,
    pub data: Value,
}

impl Row {
    pub fn new<T: Serialize>(kind: &'static str, key: impl Into<String>, data: &T) -> Row {
        Row { kind, key: key.into(), data: serde_json::to_value(data).unwrap_or(Value::Null) }
    }
}

fn db_err(e: rusqlite::Error) -> BrError {
    BrError::with_code(format!("the index could not be read or written ({e})"), Some("check BR_HOME and its permissions; br init --force rebuilds it"), 1)
}

pub fn index_path(ctx: &Ctx) -> PathBuf {
    ctx.home.join("index.db")
}

pub fn exists(ctx: &Ctx) -> bool {
    index_path(ctx).exists()
}

impl Store {
    /// Open (creating the file and tables when `create`).
    pub fn open(ctx: &Ctx, create: bool) -> BrResult<Store> {
        let path = index_path(ctx);
        if !path.exists() {
            if !create {
                return Err(BrError::no_index(&path));
            }
            std::fs::create_dir_all(&ctx.home).map_err(|e| BrError::with_code(format!("{}: {e}", ctx.home.display()), Some("check BR_HOME and its permissions"), 1))?;
        }
        let conn = Connection::open(&path).map_err(db_err)?;
        conn.busy_timeout(std::time::Duration::from_secs(30)).map_err(db_err)?;
        conn.execute_batch(SCHEMA).map_err(db_err)?;
        let st = Store { conn, path };
        match st.try_kv_get::<i64>("schema_version")? {
            None => st.kv_set("schema_version", &SCHEMA_VERSION)?,
            Some(v) if v > SCHEMA_VERSION => {
                return Err(BrError::with_code(
                    format!("the index at {} was written by a newer br (schema {v}, this br reads {SCHEMA_VERSION})", st.path.display()),
                    Some("upgrade br, or br init --force to rebuild the index"),
                    1,
                ))
            }
            _ => {}
        }
        Ok(st)
    }

    /// Delete the file and start over (`init --force`).
    pub fn reset(ctx: &Ctx) -> BrResult<Store> {
        let p = index_path(ctx);
        for ext in ["", "-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{}{}", p.display(), ext));
        }
        Store::open(ctx, true)
    }

    // ---- kv ----------------------------------------------------------------------------------------------
    pub fn kv_get<T: DeserializeOwned>(&self, k: &str) -> Option<T> {
        let s: Option<String> = self.conn.query_row("SELECT v FROM kv WHERE k=?", [k], |r| r.get(0)).optional().ok().flatten();
        s.and_then(|s| serde_json::from_str(&s).ok())
    }

    /// Like `kv_get`, but a SQL or decode error is an error, not "not there".
    pub fn try_kv_get<T: DeserializeOwned>(&self, k: &str) -> BrResult<Option<T>> {
        let s: Option<String> = self.conn.query_row("SELECT v FROM kv WHERE k=?", [k], |r| r.get(0)).optional().map_err(db_err)?;
        match s {
            None => Ok(None),
            Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| BrError::with_code(format!("the index holds an unreadable value for {k} ({e})"), Some("br init --force rebuilds it"), 1)),
        }
    }

    pub fn kv_set<T: Serialize>(&self, k: &str, v: &T) -> BrResult<()> {
        self.conn.execute("INSERT INTO kv(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", params![k, serde_json::to_string(v).unwrap()]).map_err(db_err)?;
        Ok(())
    }

    // ---- sources -----------------------------------------------------------------------------------------
    pub fn sources(&self) -> BTreeMap<String, Source> {
        let mut out = BTreeMap::new();
        let Ok(mut st) = self.conn.prepare("SELECT name,kind,reach,indexed_at,empty FROM sources WHERE removed_at IS NULL ORDER BY name") else { return out };
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, Source { kind: r.get(1)?, reach: r.get(2)?, indexed_at: r.get(3)?, empty: r.get::<_, i64>(4)? != 0, gaps: vec![] })));
        if let Ok(rows) = rows {
            for (n, s) in rows.flatten() {
                out.insert(n, s);
            }
        }
        for (n, g) in self.all_gaps() {
            if let Some(s) = out.get_mut(&n) {
                s.gaps.push(g);
            }
        }
        out
    }

    // ---- gaps: what a source's last scan could not check -------------------------------------------------
    /// Replace a source's gaps with what this scan could not check (an empty list clears them).
    pub fn set_gaps(&self, source: &str, gaps: &[crate::view::Gap]) -> BrResult<()> {
        self.conn.execute("DELETE FROM gaps WHERE source=?", params![source]).map_err(db_err)?;
        for g in gaps {
            self.conn.execute("INSERT OR REPLACE INTO gaps(source,scope,reason,at) VALUES(?,?,?,?)", params![source, g.scope, g.reason, g.at]).map_err(db_err)?;
        }
        Ok(())
    }

    fn all_gaps(&self) -> Vec<(String, crate::view::Gap)> {
        let Ok(mut st) = self.conn.prepare("SELECT source,scope,reason,at FROM gaps ORDER BY source,scope") else { return vec![] };
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, crate::view::Gap { scope: r.get(1)?, reason: r.get(2)?, at: r.get(3)? })));
        rows.map(|r| r.flatten().collect()).unwrap_or_default()
    }

    pub fn try_sources(&self) -> BrResult<BTreeMap<String, Source>> {
        let mut out = BTreeMap::new();
        let mut st = self.conn.prepare("SELECT name,kind,reach,indexed_at,empty FROM sources WHERE removed_at IS NULL ORDER BY name").map_err(db_err)?;
        let rows =
            st.query_map([], |r| Ok((r.get::<_, String>(0)?, Source { kind: r.get(1)?, reach: r.get(2)?, indexed_at: r.get(3)?, empty: r.get::<_, i64>(4)? != 0, gaps: vec![] }))).map_err(db_err)?;
        for r in rows {
            let (n, s) = r.map_err(db_err)?;
            out.insert(n, s);
        }
        let mut g = self.conn.prepare("SELECT source,scope,reason,at FROM gaps ORDER BY source,scope").map_err(db_err)?;
        let rows = g.query_map([], |r| Ok((r.get::<_, String>(0)?, crate::view::Gap { scope: r.get(1)?, reason: r.get(2)?, at: r.get(3)? }))).map_err(db_err)?;
        for r in rows {
            let (n, gap) = r.map_err(db_err)?;
            if let Some(s) = out.get_mut(&n) {
                s.gaps.push(gap);
            }
        }
        Ok(out)
    }

    pub fn source(&self, name: &str) -> Option<Source> {
        let mut src = self
            .conn
            .query_row("SELECT kind,reach,indexed_at,empty FROM sources WHERE name=? AND removed_at IS NULL", params![name], |r| {
                Ok(Source { kind: r.get(0)?, reach: r.get(1)?, indexed_at: r.get(2)?, empty: r.get::<_, i64>(3)? != 0, gaps: vec![] })
            })
            .ok()?;
        if let Ok(mut g) = self.conn.prepare("SELECT scope,reason,at FROM gaps WHERE source=? ORDER BY scope") {
            if let Ok(rows) = g.query_map(params![name], |r| Ok(crate::view::Gap { scope: r.get(0)?, reason: r.get(1)?, at: r.get(2)? })) {
                src.gaps = rows.flatten().collect();
            }
        }
        Some(src)
    }

    pub fn set_source(&self, name: &str, s: &Source, now: &str) -> BrResult<()> {
        self.conn
            .execute(
                "INSERT INTO sources(name,kind,reach,indexed_at,empty,first_seen) VALUES(?,?,?,?,?,?)
                 ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, reach=excluded.reach, indexed_at=excluded.indexed_at, empty=excluded.empty, removed_at=NULL",
                params![name, s.kind, s.reach, s.indexed_at, s.empty as i64, now],
            )
            .map_err(db_err)?;
        Ok(())
    }

    /// Take a source out of the index; its observations are marked removed so a later import starts clean.
    pub fn remove_source(&self, name: &str, now: &str) -> BrResult<()> {
        self.conn.execute("UPDATE sources SET removed_at=? WHERE name=?", params![now, name]).map_err(db_err)?;
        self.conn.execute("UPDATE obs SET removed_at=? WHERE source=? AND removed_at IS NULL", params![now, name]).map_err(db_err)?;
        Ok(())
    }

    // ---- observations ------------------------------------------------------------------------------------
    /// The present rows of one kind in one source: key -> data.
    pub fn present(&self, source: &str, kind: &str) -> BTreeMap<String, Value> {
        let mut out = BTreeMap::new();
        if let Ok(mut st) = self.conn.prepare("SELECT key,data FROM obs WHERE source=? AND kind=? AND removed_at IS NULL") {
            if let Ok(rows) = st.query_map(params![source, kind], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
                for (k, d) in rows.flatten() {
                    if let Ok(v) = serde_json::from_str(&d) {
                        out.insert(k, v);
                    }
                }
            }
        }
        out
    }

    /// Record what a source says now. Rows of `kinds` in `source` that are not in `rows` are marked removed.
    pub fn replace(&mut self, source: &str, kinds: &[&str], rows: Vec<Row>, now: &str) -> BrResult<()> {
        let tx = self.conn.transaction().map_err(db_err)?;
        let mut seen: std::collections::HashSet<(String, String)> = Default::default();
        for r in &rows {
            let d = serde_json::to_string(&r.data).unwrap();
            tx.execute(
                "INSERT INTO obs(source,kind,key,data,first_seen,last_seen) VALUES(?,?,?,?,?,?)
                 ON CONFLICT(source,kind,key) DO UPDATE SET data=excluded.data, last_seen=excluded.last_seen, removed_at=NULL",
                params![source, r.kind, r.key, d, now, now],
            )
            .map_err(db_err)?;
            seen.insert((r.kind.to_string(), r.key.clone()));
        }
        for k in kinds {
            let old: Vec<String> = {
                let mut st = tx.prepare("SELECT key FROM obs WHERE source=? AND kind=? AND removed_at IS NULL").map_err(db_err)?;
                let it = st.query_map(params![source, k], |r| r.get::<_, String>(0)).map_err(db_err)?;
                it.flatten().collect()
            };
            for key in old {
                if !seen.contains(&(k.to_string(), key.clone())) {
                    tx.execute("UPDATE obs SET removed_at=? WHERE source=? AND kind=? AND key=?", params![now, source, k, key]).map_err(db_err)?;
                }
            }
        }
        tx.commit().map_err(db_err)?;
        Ok(())
    }

    // ---- br's own state ----------------------------------------------------------------------------------
    pub fn push(&self, table: &str, v: &Value) -> BrResult<()> {
        self.conn.execute(&format!("INSERT INTO {table}(data) VALUES(?)"), [serde_json::to_string(v).unwrap()]).map_err(db_err)?;
        Ok(())
    }

    pub fn list(&self, table: &str) -> Vec<Value> {
        let mut out = vec![];
        if let Ok(mut st) = self.conn.prepare(&format!("SELECT data FROM {table} ORDER BY id")) {
            if let Ok(rows) = st.query_map([], |r| r.get::<_, String>(0)) {
                for d in rows.flatten() {
                    if let Ok(v) = serde_json::from_str(&d) {
                        out.push(v);
                    }
                }
            }
        }
        out
    }

    pub fn try_list(&self, table: &str) -> BrResult<Vec<Value>> {
        let mut st = self.conn.prepare(&format!("SELECT data FROM {table} ORDER BY id")).map_err(db_err)?;
        let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(db_err)?;
        let mut out = vec![];
        for d in rows {
            let d = d.map_err(db_err)?;
            out.push(serde_json::from_str(&d).map_err(|e| BrError::with_code(format!("the index holds an unreadable {table} row ({e})"), Some("br init --force rebuilds it"), 1))?);
        }
        Ok(out)
    }

    pub fn try_imports(&self) -> BrResult<BTreeMap<String, Value>> {
        let mut st = self.conn.prepare("SELECT host,data FROM imports").map_err(db_err)?;
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).map_err(db_err)?;
        let mut out = BTreeMap::new();
        for r in rows {
            let (h, d) = r.map_err(db_err)?;
            let v = serde_json::from_str(&d).map_err(|e| BrError::with_code(format!("the index holds an unreadable import for {h} ({e})"), Some("br init --force rebuilds it"), 1))?;
            out.insert(h, v);
        }
        Ok(out)
    }

    pub fn imports(&self) -> BTreeMap<String, Value> {
        let mut out = BTreeMap::new();
        if let Ok(mut st) = self.conn.prepare("SELECT host,data FROM imports") {
            if let Ok(rows) = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))) {
                for (h, d) in rows.flatten() {
                    if let Ok(v) = serde_json::from_str(&d) {
                        out.insert(h, v);
                    }
                }
            }
        }
        out
    }

    pub fn set_import(&self, host: &str, v: &Value) -> BrResult<()> {
        self.conn.execute("INSERT INTO imports(host,data) VALUES(?,?) ON CONFLICT(host) DO UPDATE SET data=excluded.data", params![host, serde_json::to_string(v).unwrap()]).map_err(db_err)?;
        Ok(())
    }

    pub fn drop_import(&self, host: &str) -> BrResult<()> {
        self.conn.execute("DELETE FROM imports WHERE host=?", [host]).map_err(db_err)?;
        Ok(())
    }
}

// ---- the View ----------------------------------------------------------------------------------------------
fn all_obs(st: &Store) -> BrResult<Vec<(String, String, String, Value)>> {
    let mut out = vec![];
    let mut q = st.conn.prepare("SELECT source,kind,key,data FROM obs WHERE removed_at IS NULL ORDER BY source,kind,key").map_err(db_err)?;
    let rows = q.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?, r.get::<_, String>(3)?))).map_err(db_err)?;
    for r in rows {
        let (s, k, key, d) = r.map_err(db_err)?;
        let v = serde_json::from_str(&d).map_err(|e| BrError::with_code(format!("the index holds an unreadable {k} row for {s} ({e})"), Some("br init --force rebuilds it"), 1))?;
        out.push((s, k, key, v));
    }
    Ok(out)
}

fn from<T: DeserializeOwned>(v: Value) -> BrResult<T> {
    serde_json::from_value(v).map_err(|e| BrError::with_code(format!("the index holds a row br cannot read ({e})"), Some("br init --force rebuilds it"), 1))
}

/// Everything present in the store, as a View. `now` is the clock; each source is cut at its own `indexed_at`
/// (which was never later than the clock when it was written).
pub fn load_view(ctx: &Ctx) -> BrResult<View> {
    let st = Store::open(ctx, false)?;
    let mut sources = st.try_sources()?;
    for s in sources.values_mut() {
        if s.indexed_at.as_str() > ctx.now.as_str() {
            s.indexed_at = ctx.now.clone();
        }
    }
    let mut v = View { now: ctx.now.clone(), sources: sources.clone(), ..Default::default() };
    if let Some(o) = st.try_kv_get::<Org>("org")? {
        v.org = o;
    }
    v.org_admins = st.try_kv_get("org_admins")?.unwrap_or_default();
    v.org_secrets = st.try_kv_get("org_secrets")?.unwrap_or_default();
    v.secret_scopes = st.try_kv_get("org_secret_scopes")?.unwrap_or_default();
    if st.try_kv_get::<bool>("org_secrets_unreadable")?.unwrap_or(false) {
        v.secrets_unreadable.push("org".to_string());
    }
    let teams_cfg = crate::collect::config::teams(ctx);
    for (src, kind, key, d) in all_obs(&st)? {
        if src != ORG && !sources.contains_key(&src) {
            continue;
        }
        let cut = sources.get(&src).map(|s| s.indexed_at.clone());
        match kind.as_str() {
            "person" => v.people.push(from(d)?),
            "team" => {
                let mut t: Team = from(d)?;
                if let Some(c) = teams_cfg.get(&t.id) {
                    if c.slack.is_some() {
                        t.slack = c.slack.clone();
                    }
                    if c.jira.is_some() {
                        t.jira = c.jira.clone();
                    }
                }
                v.teams.push(t)
            }
            "repo" => {
                let r: Repo = from(d)?;
                let e = v.repos.entry(key).or_default();
                let (c, ru, ca, ar, re) =
                    (std::mem::take(&mut e.commits), std::mem::take(&mut e.runs), std::mem::take(&mut e.caches), std::mem::take(&mut e.artifacts), std::mem::take(&mut e.releases));
                let trust = std::mem::take(&mut e.trust);
                *e = r;
                e.trust = trust;
                e.commits = c;
                e.runs = ru;
                e.caches = ca;
                e.artifacts = ar;
                e.releases = re;
            }
            "commit" | "run" | "cache" | "artifact" | "release" => {
                let r = v.repos.entry(src.clone()).or_default();
                let before = |t: &str| cut.as_deref().map(|c| t <= c).unwrap_or(true);
                match kind.as_str() {
                    "commit" => {
                        let c: Commit = from(d)?;
                        if before(&c.at) {
                            r.commits.push(c)
                        }
                    }
                    "run" => {
                        let c: Run = from(d)?;
                        if before(&c.at) {
                            r.runs.push(c)
                        }
                    }
                    "cache" => {
                        let c: Cache = from(d)?;
                        if before(&c.created) {
                            r.caches.push(c)
                        }
                    }
                    "artifact" => {
                        let c: Artifact = from(d)?;
                        if before(&c.created) {
                            r.artifacts.push(c)
                        }
                    }
                    _ => {
                        let c: Release = from(d)?;
                        if before(&c.published) {
                            r.releases.push(c)
                        }
                    }
                }
            }
            "host" => {
                let mut h: Host = from(d)?;
                h.kind = h.kind.as_deref().map(|k| view_kind(k).to_string());
                let e = v.hosts.entry(key).or_default();
                let items = std::mem::take(&mut e.items);
                let declared = std::mem::take(&mut e.declared);
                let trust = std::mem::take(&mut e.trust);
                *e = h;
                e.trust = trust;
                e.items = items;
                e.declared = declared;
            }
            "item" => {
                // What a lockfile item's file declares travels in its row
                let decl = d.get("declared").and_then(|x| serde_json::from_value::<Vec<LockPackage>>(x.clone()).ok());
                let it: HostItem = from(d)?;
                if cut.as_deref().map(|c| it.at.as_str() <= c).unwrap_or(true) {
                    let h = v.hosts.entry(src.clone()).or_default();
                    if let Some(packages) = decl {
                        h.declared.push(DeclaredLock { loc: it.loc.clone(), packages });
                    }
                    h.items.push(it);
                }
            }
            "trust" => {
                // A certificate file read at a repo's HEAD or on a host; a note or a call count belongs to the place
                let set =
                    if sources.get(&src).map(|s| s.kind == "repo").unwrap_or(false) { &mut v.repos.entry(src.clone()).or_default().trust } else { &mut v.hosts.entry(src.clone()).or_default().trust };
                if let Some(n) = d.get("note").and_then(|x| x.as_str()) {
                    set.notes.push(n.to_string());
                } else if d.get("read").is_some() || d.get("api_calls").is_some() {
                    set.read = true;
                    set.api_calls = d.get("api_calls").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
                } else {
                    set.files.push(from(d)?);
                }
            }
            "image" => {
                let b: ImageBuild = from(d)?;
                if cut.as_deref().map(|c| b.built.as_str() <= c).unwrap_or(true) {
                    v.images.push(b);
                }
            }
            _ => {}
        }
    }
    // hosts that are sources but have no observations still appear
    for (n, s) in &sources {
        if s.kind == "host" {
            v.hosts.entry(n.clone()).or_default();
        }
        if s.kind == "repo" {
            v.repos.entry(n.clone()).or_default();
        }
    }
    v.people.sort_by(|a, b| a.login.cmp(&b.login));
    v.teams.sort_by(|a, b| a.id.cmp(&b.id));
    // Teams the operator routed with `br teams set` that GitHub does not list
    v.routed_teams = teams_cfg.keys().filter(|id| !v.teams.iter().any(|t| &t.id == *id)).cloned().collect();
    v.routed_teams.sort();
    v.org_admins.sort();
    for r in v.repos.values_mut() {
        r.commits.sort_by(|a, b| a.at.cmp(&b.at).then(a.sha.cmp(&b.sha)));
        r.runs.sort_by_key(|a| a.id);
        r.caches.sort_by(|a, b| a.created.cmp(&b.created).then(a.key.cmp(&b.key)));
        r.artifacts.sort_by_key(|a| a.id);
        r.releases.sort_by(|a, b| a.published.cmp(&b.published).then(a.tag.cmp(&b.tag)));
    }
    for r in v.repos.values_mut() {
        r.trust.files.sort_by(|a, b| a.path.cmp(&b.path));
        r.trust.notes.sort();
    }
    for h in v.hosts.values_mut() {
        h.trust.files.sort_by(|a, b| a.path.cmp(&b.path));
        h.trust.notes.sort();
        h.items.sort_by(|a, b| a.at.cmp(&b.at).then(a.loc.cmp(&b.loc)).then(a.kind.cmp(&b.kind)));
    }
    v.images.sort_by(|a, b| a.repository.cmp(&b.repository).then(a.built.cmp(&b.built)));
    // the run that pushed an image: found by the digest in the run's log, whatever order the sources were read in
    let mut pushed: BTreeMap<(String, String), u64> = BTreeMap::new();
    for (name, repo) in &v.repos {
        for r in &repo.runs {
            for p in &r.produced_images {
                pushed.insert((name.clone(), p.clone()), r.id);
            }
        }
    }
    for b in v.images.iter_mut() {
        let key = format!("{}@{}", b.repository, b.digest);
        if let Some(src) = b.source.as_mut() {
            if let Some(repo) = src.repo.clone() {
                if let Some(id) = pushed.get(&(repo, key)) {
                    src.run = Some(*id);
                }
            }
        }
    }
    for (n, c) in crate::collect::config::hosts(ctx) {
        if let Some(h) = v.hosts.get_mut(&n) {
            if c.owner.is_some() {
                h.owner = c.owner.clone();
            }
            if c.owner_team.is_some() {
                h.owner_team = c.owner_team.clone();
            }
            if let Some(k) = &c.kind {
                h.kind = Some(view_kind(k).to_string());
            }
        }
    }
    v.state.imports = st.try_imports()?;
    // The roots each host's scans read, and the one decision about which host is this machine
    for (n, im) in &v.state.imports {
        if let Some(h) = v.hosts.get_mut(n) {
            h.roots = im["roots"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
            h.this_machine = im["this_machine"].as_bool().unwrap_or(false);
            h.home = im["home"].as_str().filter(|s| !s.is_empty()).map(str::to_string);
        }
    }
    for h in v.hosts.values_mut() {
        h.declared.sort_by(|a, b| a.loc.cmp(&b.loc));
    }
    v.state.custody = st.try_list("custody")?;
    v.state.scans = st.try_list("scans")?;
    v.state.yara_hits = st.try_list("yara_hits")?;
    v.state.last_scan = st.try_kv_get("last_scan")?;
    v.advisories = crate::collect::config::advisories(ctx, &st);
    Ok(v)
}

/// The View's host kind for a `br hosts add --kind` value.
/// The vocabulary is runner, laptop or server; anything else (or nothing) is "host". A name never decides kind.
pub fn view_kind(k: &str) -> &'static str {
    match k.trim().to_lowercase().as_str() {
        "runner" | "ci-runner" | "ci" => "runner",
        "laptop" | "dev-laptop" => "laptop",
        "server" => "server",
        _ => "host",
    }
}
