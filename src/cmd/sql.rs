//! `br sql`.

use rusqlite::types::Value;

use crate::cli::SqlArgs;
use crate::ctx::Ctx;
use crate::error::{BrError, BrResult};
use crate::out::sqlcmd as S;
use crate::query::index::Index;

fn sqlite_msg(e: &rusqlite::Error) -> String {
    match e {
        rusqlite::Error::MultipleStatement => "You can only execute one statement at a time.".to_string(),
        rusqlite::Error::SqliteFailure(_, Some(m)) => m.clone(),
        rusqlite::Error::SqlInputError { msg, .. } => msg.clone(),
        e => e.to_string(),
    }
}

/// The built database is cached next to the index and reused while the index file is unchanged (its size and mtime, and the
/// -wal file's, are the key). A 5000-repo index is then built once, not on every query.
fn cache_key(ctx: &Ctx) -> Option<String> {
    if std::env::var_os("BR_DEV_VIEW").is_some() {
        return None;
    }
    let mut key = String::from(env!("CARGO_PKG_VERSION"));
    for ext in ["", "-wal"] {
        let p = ctx.home.join(format!("index.db{ext}"));
        match std::fs::metadata(&p) {
            Ok(m) => {
                let t = m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_nanos());
                key += &format!("-{}-{t}", m.len());
            }
            Err(_) if ext.is_empty() => return None,
            Err(_) => key += "-0",
        }
    }
    // the built tables depend on the clock only through what the index says is current; the date keeps a stale day apart
    key += &format!("-{}", ctx.now.get(..10).unwrap_or(""));
    Some(key.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect())
}

fn open_cached(ctx: &Ctx, key: &Option<String>) -> Option<rusqlite::Connection> {
    let p = ctx.home.join(format!("sql-cache-{}.db", key.as_ref()?));
    p.exists().then(|| rusqlite::Connection::open_with_flags(&p, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).ok()).flatten()
}

fn store_cache(ctx: &Ctx, db: &rusqlite::Connection, key: &Option<String>) {
    let Some(k) = key else { return };
    if let Ok(rd) = std::fs::read_dir(&ctx.home) {
        for e in rd.flatten() {
            let n = e.file_name().to_string_lossy().to_string();
            if n.starts_with("sql-cache-") && n.ends_with(".db") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
    let p = ctx.home.join(format!("sql-cache-{k}.db"));
    let tmp = ctx.home.join(format!("sql-cache-{k}.tmp{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    // VACUUM INTO writes a compact copy of the in-memory database to a new file (SQLite 3.27+)
    if db.execute("VACUUM INTO ?1", [tmp.to_string_lossy().to_string()]).is_ok() {
        let _ = std::fs::rename(&tmp, &p);
    }
    let _ = std::fs::remove_file(&tmp);
}

pub fn run(a: &SqlArgs, ctx: &Ctx) -> BrResult<i32> {
    if a.schema {
        println!("{}", S::SCHEMA);
        return Ok(0);
    }
    let q = a.query.clone().unwrap_or_default();
    if q.trim().is_empty() {
        return Err(BrError::new("no query given", Some("example: br sql 'SELECT name FROM sources'")));
    }
    // .tables, .schema and the like are sqlite shell commands; br sql takes SQL, and --schema lists what can be asked
    if q.trim_start().starts_with('.') {
        return Err(BrError::new(
            format!("{} is a sqlite shell command, not SQL", q.split_whitespace().next().unwrap_or("")),
            Some("br sql --schema lists the tables and columns; then br sql 'SELECT ... FROM table'"),
        ));
    }
    let view_key = cache_key(ctx);
    let db = match open_cached(ctx, &view_key) {
        Some(db) => db,
        None => {
            let view = ctx.view()?;
            let ix = Index::new(&view, &ctx.now);
            let db = S::build(&ix).map_err(|e| BrError::new(sqlite_msg(&e), None))?;
            store_cache(ctx, &db, &view_key);
            db
        }
    };
    let bad = |e: rusqlite::Error| BrError::new(sqlite_msg(&e), Some("br sql --schema lists the tables"));
    // read-only is decided by SQLite, not by the first word of the text: a leading comment, parentheses, VALUES and
    // PRAGMA table_info all work, and a WITH ... DELETE is refused
    db.execute_batch("PRAGMA query_only = 1").map_err(bad)?;
    let mut stmt = db.prepare(&q).map_err(bad)?;
    if !stmt.readonly() {
        return Err(BrError::new("the index is read-only through br sql", Some("only statements that read are accepted")));
    }
    let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let nc = cols.len();
    let mut rows: Vec<Vec<Value>> = vec![];
    let mut it = stmt.query([]).map_err(bad)?;
    while let Some(r) = it.next().map_err(bad)? {
        rows.push((0..nc).map(|i| r.get::<_, Value>(i)).collect::<Result<_, _>>().map_err(bad)?);
    }
    let out = match a.format.as_str() {
        "json" => S::render_json(&cols, &rows),
        "csv" => S::render_csv(&cols, &rows),
        _ => S::render_table(&cols, &rows),
    };
    println!("{out}");
    Ok(0)
}
